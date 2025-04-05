package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	// "golang.org/x/net/websocket"
)

// --- Constants and Configuration ---

var (
	authRequired           bool
	port                   string
	cloudflareAppID        string
	cloudflareAppSecret    string
	secretKey              string
	cloudflareCallsBaseURL string
	cloudflareBasePath     string
	debug                  bool
)

func initConfig() {
	err := godotenv.Load() // Load .env file
	if err != nil {
		log.Println("Warning: Could not load .env file:", err) // Don't fatal, as we have defaults
	}

	// authRequired = getEnvBool("AUTH_REQUIRED", true)
	authRequired = false
	port = getEnv("PORT", "5000")
	cloudflareAppID = getEnv("CLOUDFLARE_APP_ID", "")
	cloudflareAppSecret = getEnv("CLOUDFLARE_APP_SECRET", "")
	secretKey = getEnv("JWT_SECRET", "thisisjustademokey")
	cloudflareCallsBaseURL = getEnv("CLOUDFLARE_APPS_URL", "https://rtc.live.cloudflare.com/v1/apps")
	cloudflareBasePath = fmt.Sprintf("%s/%s", cloudflareCallsBaseURL, cloudflareAppID)
	debug = getEnvBool("DEBUG", false)

	if cloudflareAppID == "" || cloudflareAppSecret == "" {
		log.Fatal("CLOUDFLARE_APP_ID and CLOUDFLARE_APP_SECRET must be set")
	}

	// Thêm log để kiểm tra biến môi trường
	log.Println("Biến môi trường đã tải:")
	log.Println("CLOUDFLARE_APP_ID:", cloudflareAppID)
	log.Println("CLOUDFLARE_APP_SECRET:", cloudflareAppSecret)
	log.Println("JWT_SECRET:", secretKey)
	log.Println("CLOUDFLARE_APPS_URL:", cloudflareCallsBaseURL)
	log.Println("DEBUG:", debug)
}

// Helper function to get environment variables with default values
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func init() {
	// Initialize maps
	rooms.m = make(map[string]*Room)
	users.m = make(map[string]*User)
	wsConnections.m = make(map[string]map[string]*websocket.Conn)
}

// Helper function to get boolean environment variables
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue // Return default if parsing fails
	}
	return b
}

// --- Data Structures ---

type Room struct {
	RoomId       string                 `json:"roomId"` // Thêm trường này
	Name         string                 `json:"name"`
	Metadata     map[string]interface{} `json:"metadata"`
	Participants []*Participant         `json:"participants"`
	CreatedAt    int64                  `json:"createdAt"`
	sync.RWMutex                        // Protects concurrent access to the room
}

type Participant struct {
	UserID          string   `json:"userId"`
	SessionID       string   `json:"sessionId"`
	CreatedAt       int64    `json:"createdAt"`
	PublishedTracks []string `json:"publishedTracks"`
}

type User struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	IsModerator bool   `json:"isModerator"`
	Role        string `json:"role"`
}

type SessionResponse struct {
	SessionId     string        `json:"sessionId"`
	OtherSessions []SessionInfo `json:"otherSessions"`
}

type SessionInfo struct {
	UserId          string   `json:"userId"`
	SessionId       string   `json:"sessionId"`
	PublishedTracks []string `json:"publishedTracks"`
}

// Use a concurrent-safe map for rooms.
var rooms = struct {
	sync.RWMutex
	m map[string]*Room
}{m: make(map[string]*Room)}

var users = struct {
	sync.RWMutex
	m map[string]*User
}{m: make(map[string]*User)}

var wsConnections = struct {
	sync.RWMutex
	m map[string]map[string]*websocket.Conn
}{m: make(map[string]map[string]*websocket.Conn)}

// --- JWT Verification Middleware ---
func verifyToken(c *gin.Context) {
	if !authRequired {
		// Even when auth is disabled, set a default user
		defaultUser := &User{
			UserID:      uuid.NewString(),
			Username:    "Anonymous",
			Role:        "demo",
			IsModerator: true,
		}
		// Store user in users map
		users.Lock()
		users.m[defaultUser.UserID] = defaultUser
		users.Unlock()

		c.Set("user", defaultUser)
		c.Next()
		return
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "*" {
		defaultUser := &User{
			UserID:      uuid.NewString(),
			Username:    "Anonymous",
			Role:        "demo",
			IsModerator: true,
		}

		// Store user in users map
		users.Lock()
		users.m[defaultUser.UserID] = defaultUser
		users.Unlock()

		c.Set("user", defaultUser)
		c.Next()
		return
	}

	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: No token provided"})
		return
	}

	tokenString := authHeader[7:]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid token"})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//convert claims to user
		userId, ok1 := claims["userId"].(string)
		username, ok2 := claims["username"].(string)
		role, ok3 := claims["role"].(string)
		isModerator, ok4 := claims["isModerator"].(bool)
		if ok1 && ok2 && ok3 && ok4 {
			c.Set("user", &User{
				UserID:      userId,
				Username:    username,
				Role:        role,
				IsModerator: isModerator,
			})
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid token claims"})
		}
	} else {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid token"})
	}
}

// --- Cloudflare API Interaction Functions ---

func createCloudflareSession() (string, error) {
	url := fmt.Sprintf("%s/sessions/new", cloudflareBasePath)
	log.Printf("[Cloudflare API] Creating new session: %s", url)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to create request: %v", err)
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to execute request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to read response body: %v", err)
		return "", err
	}

	log.Printf("[Cloudflare API Response] Status: %d, Body: %s", resp.StatusCode, string(body))

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		log.Printf("[Cloudflare API Error] Failed to parse response: %v", err)
		return "", err
	}

	sessionID, ok := responseData["sessionId"].(string)
	if !ok {
		log.Printf("[Cloudflare API Error] Session ID not found in response")
		return "", fmt.Errorf("sessionId not found in response: %s", string(body))
	}

	log.Printf("[Cloudflare API Success] Created session: %s", sessionID)
	return sessionID, nil
}

func makeCloudflareRequest(method string, url string, requestBody map[string]interface{}) (map[string]interface{}, error, int) {
	var reqBodyBytes []byte = nil
	if requestBody != nil {
		var errMarshal error
		reqBodyBytes, errMarshal = json.Marshal(requestBody)
		if errMarshal != nil {
			log.Printf("Lỗi Marshal body yêu cầu JSON: %v", errMarshal)
			return nil, errMarshal, http.StatusInternalServerError
		}
	}

	req, errNewRequest := http.NewRequest(method, url, bytes.NewBuffer(reqBodyBytes))
	if errNewRequest != nil {
		log.Printf("Lỗi tạo yêu cầu HTTP mới: %v", errNewRequest)
		return nil, errNewRequest, http.StatusInternalServerError
	}

	// Thiết lập các header quan trọng và phổ biến
	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret) // Đảm bảo cloudflareAppSecret có giá trị
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json") // Cho các yêu cầu có body JSON
	}
	req.Header.Set("Accept", "application/json")               // Yêu cầu phản hồi JSON
	req.Header.Set("User-Agent", "CloudflareCalls-Backend-Go") // Thêm User-Agent để nhận diện backend (tùy chọn)
	// Bạn có thể thêm các header khác nếu cần, ví dụ:
	// req.Header.Set("Cache-Control", "no-cache")
	// req.Header.Set("Connection", "keep-alive")

	log.Println("Yêu cầu HTTP:")
	log.Println("  Method:", method)
	log.Println("  URL:", url)
	log.Println("  Headers:", req.Header)
	if requestBody != nil {
		log.Println("  Body yêu cầu:", string(reqBodyBytes))
	}

	client := &http.Client{}
	resp, errClientDo := client.Do(req)
	if errClientDo != nil {
		log.Printf("Lỗi khi thực hiện yêu cầu HTTP: %v", errClientDo)
		return nil, errClientDo, http.StatusInternalServerError
	}
	defer resp.Body.Close()

	respBodyBytes, errReadAll := io.ReadAll(resp.Body)
	if errReadAll != nil {
		log.Printf("Lỗi đọc body phản hồi: %v", errReadAll)
		return nil, errReadAll, http.StatusInternalServerError
	}

	log.Println("Phản hồi HTTP:")
	log.Println("  Mã trạng thái:", resp.StatusCode)
	log.Println("  Body phản hồi:", string(respBodyBytes))

	var responseData map[string]interface{}
	errUnmarshal := json.Unmarshal(respBodyBytes, &responseData)
	if errUnmarshal != nil {
		log.Printf("Lỗi Unmarshal body phản hồi JSON: %v", errUnmarshal)
		return nil, errUnmarshal, http.StatusInternalServerError
	}

	return responseData, nil, resp.StatusCode
}

func publishToCloudflare(sessionId string, offer map[string]interface{}, tracks []struct {
	TrackName string `json:"trackName"`
	Mid       string `json:"mid"`
	Location  string `json:"location"`
}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/sessions/%s/tracks/new", cloudflareBasePath, sessionId)
	log.Printf("[Cloudflare API] Publishing tracks to session %s", sessionId)

	trackData := make([]map[string]interface{}, len(tracks))
	for i, t := range tracks {
		location := t.Location
		if location == "" {
			location = "local"
		}
		trackData[i] = map[string]interface{}{
			"trackName": t.TrackName,
			"mid":       t.Mid,
			"location":  location,
		}
	}

	requestBody := map[string]interface{}{
		"sessionDescription": offer,
		"tracks":             trackData,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to marshal request body: %v", err)
		return nil, err
	}

	log.Printf("[Cloudflare API Request] URL: %s, Body: %s", url, string(jsonData))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to create request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to execute request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to read response body: %v", err)
		return nil, err
	}

	log.Printf("[Cloudflare API Response] Status: %d, Body: %s", resp.StatusCode, string(body))

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		log.Printf("[Cloudflare API Error] Failed to parse response: %v", err)
		return nil, err
	}

	return responseData, nil
}

func unpublishToCloudflare(cfUrl string, requestBody map[string]interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", cfUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var responseData map[string]interface{}

	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}
	return responseData, nil
}

func pullFromCloudflare(sessionId string, tracksToPull []map[string]interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/sessions/%s/tracks/new", cloudflareBasePath, sessionId)

	requestBody := map[string]interface{}{
		"tracks": tracksToPull,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil
}

func renegotiateWithCloudflare(sessionId string, body map[string]interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/sessions/%s/renegotiate", cloudflareBasePath, sessionId)

	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseData); err != nil {
		return nil, err
	}
	return responseData, nil
}

func manageDataChannelsWithCloudflare(cfUrl string, dataChannels []map[string]interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(gin.H{"dataChannels": dataChannels}) // Correct structure
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", cfUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil
}

func getSessionStateFromCloudflare(sessionId string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/sessions/%s", cloudflareBasePath, sessionId)
	log.Printf("[Cloudflare API] Getting session state: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to create request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to execute request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Cloudflare API Error] Failed to read response body: %v", err)
		return nil, err
	}

	log.Printf("[Cloudflare API Response] Status: %d, Body: %s", resp.StatusCode, string(body))

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		log.Printf("[Cloudflare API Error] Failed to parse response: %v", err)
		return nil, err
	}

	return responseData, nil
}

// --- Helper Functions ---

func serializeRoom(roomId string, room *Room) gin.H {
	return gin.H{
		"roomId":           roomId,
		"name":             room.Name,
		"metadata":         room.Metadata,
		"participantCount": len(room.Participants),
		"createdAt":        room.CreatedAt,
	}
}

// --- Route Handlers ---

func createRoom(c *gin.Context) {
	roomId := uuid.NewString()
	var req struct {
		Name     string                 `json:"name"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	room := &Room{
		RoomId:       roomId, // Thêm trường này
		Name:         req.Name,
		Metadata:     req.Metadata,
		Participants: []*Participant{},
		CreatedAt:    time.Now().Unix(),
	}

	rooms.Lock()
	rooms.m[roomId] = room
	rooms.Unlock()

	// Trả về format giống Express
	c.JSON(http.StatusOK, gin.H{
		"roomId":           room.RoomId,
		"name":             room.Name,
		"metadata":         room.Metadata,
		"participantCount": len(room.Participants),
		"createdAt":        room.CreatedAt,
	})
}

func inspectRooms(c *gin.Context) {
	if os.Getenv("NODE_ENV") != "development" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This endpoint is only available in development mode."})
		return
	}

	rooms.RLock()
	defer rooms.RUnlock()

	users.RLock()
	defer users.RUnlock()

	wsConnections.RLock()
	defer wsConnections.RUnlock()

	debugInfo := gin.H{
		"rooms":         rooms.m,
		"roomCount":     len(rooms.m),
		"users":         users.m,         // Convert to a slice or similar for JSON
		"wsConnections": wsConnections.m, // You might want to just show counts
		"raw":           rooms.m,
	}
	c.JSON(http.StatusOK, debugInfo)
}

func joinRoom(c *gin.Context) {
	roomId := c.Param("roomId")
	user, _ := c.Get("user")
	currentUser, ok := user.(*User)
	if !ok {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid user"})
		return
	}
	userId := currentUser.UserID

	rooms.Lock() // Lock for writing
	room, exists := rooms.m[roomId]
	if !exists {
		// Create new room if it doesn't exist
		room = &Room{
			Name:         "New Room",
			Metadata:     make(map[string]interface{}),
			Participants: make([]*Participant, 0),
			CreatedAt:    time.Now().Unix(),
		}
		rooms.m[roomId] = room
	}
	rooms.Unlock()

	// Create Calls Session
	sessionID, err := createCloudflareSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create Calls session"})
		return
	}

	participant := &Participant{
		UserID:          userId,
		SessionID:       sessionID,
		CreatedAt:       time.Now().Unix(),
		PublishedTracks: make([]string, 0),
	}

	room.Lock()
	room.Participants = append(room.Participants, participant)

	// Create otherSessions list safely with complete track information
	otherSessions := make([]SessionInfo, 0)
	for _, p := range room.Participants {
		if p.UserID != userId {
			// Lấy state của session từ Cloudflare để có thông tin track đầy đủ
			state, err := getSessionStateFromCloudflare(p.SessionID)
			if err != nil {
				log.Printf("Error getting session state for %s: %v", p.SessionID, err)
				continue
			}

			// Extract tracks info from state
			tracks := make([]string, 0)
			if tracksArray, ok := state["tracks"].([]interface{}); ok {
				for _, track := range tracksArray {
					if trackMap, ok := track.(map[string]interface{}); ok {
						if trackName, ok := trackMap["trackName"].(string); ok {
							tracks = append(tracks, trackName)
						}
					}
				}
			}

			otherSessions = append(otherSessions, SessionInfo{
				UserId:          p.UserID,
				SessionId:       p.SessionID,
				PublishedTracks: tracks,
			})
		}
	}
	room.Unlock()

	// Initialize WebSocket connections map for the room
	wsConnections.Lock()
	if _, exists := wsConnections.m[roomId]; !exists {
		wsConnections.m[roomId] = make(map[string]*websocket.Conn)
	}
	wsConnections.Unlock()

	// Add more detail to the participant-joined event
	broadcastToRoom(roomId, gin.H{
		"type": "participant-joined",
		"payload": gin.H{
			"userId":    userId,
			"username":  currentUser.Username,
			"sessionId": sessionID,
		},
	}, userId)

	response := SessionResponse{
		SessionId:     sessionID,
		OtherSessions: otherSessions,
	}

	if debug {
		log.Printf("Join room response: %+v\n", response)
	}

	c.JSON(http.StatusOK, response)
}

// Sửa lại struct request cho publishTracks để match với Express
func publishTracks(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")

	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}

	var participant *Participant
	room.RLock()
	for _, p := range room.Participants {
		if p.SessionID == sessionId {
			participant = p
			break
		}
	}
	room.RUnlock()
	if participant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found in this room"})
		return
	}

	var req struct {
		Offer  map[string]interface{} `json:"offer"`
		Tracks []struct {
			TrackName string `json:"trackName"`
			Mid       string `json:"mid"` // Thêm mid
			Location  string `json:"location"`
		} `json:"tracks"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if debug {
		log.Printf("Publishing tracks for session %s: %+v\n", sessionId, req.Tracks)
	}

	// Prepare track data for Cloudflare API
	tracks := make([]map[string]interface{}, len(req.Tracks))
	trackNames := make([]string, len(req.Tracks))
	for i, t := range req.Tracks {
		location := t.Location
		if location == "" {
			location = "local"
		}
		tracks[i] = map[string]interface{}{
			"trackName": t.TrackName,
			"location":  location,
			"mid":       t.Mid,
		}
		trackNames[i] = t.TrackName
	}

	// Call Cloudflare API
	requestBody := map[string]interface{}{
		"sessionDescription": req.Offer,
		"tracks":             tracks,
	}

	url := fmt.Sprintf("%s/sessions/%s/tracks/new", cloudflareBasePath, sessionId)
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cfReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cfReq.Header.Set("Authorization", "Bearer "+cloudflareAppSecret)
	cfReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(cfReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update participant's published tracks
	room.Lock()
	for _, t := range req.Tracks {
		if !contains(participant.PublishedTracks, t.TrackName) {
			participant.PublishedTracks = append(participant.PublishedTracks, t.TrackName)
		}
	}
	room.Unlock()

	// Broadcast track-published event with complete information
	if data["sessionDescription"] != nil {
		broadcastToRoom(roomId, gin.H{
			"type": "track-published",
			"payload": gin.H{
				"userId":    participant.UserID,
				"sessionId": sessionId,
				"tracks":    trackNames,
			},
		}, participant.UserID)

		if debug {
			log.Printf("Track published event broadcasted for session %s with tracks: %v\n", sessionId, trackNames)
		}
	}

	c.JSON(http.StatusOK, data)
}

// Helper function to check if slice contains string
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func unpublishTrack(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")
	user, _ := c.Get("user")
	currentUser, ok := user.(*User)
	if !ok {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid user"})
		return
	}

	var req struct {
		TrackName          string                 `json:"trackName"`
		Mid                string                 `json:"mid"`
		Force              bool                   `json:"force"`
		SessionDescription map[string]interface{} `json:"sessionDescription"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	//If trying to force unpublish someone else's track
	if req.Force && sessionId != currentUser.UserID {
		//Check if user is moderator
		if !currentUser.IsModerator {
			c.JSON(http.StatusForbidden, gin.H{
				"errorCode":        "NOT_AUTHORIZED",
				"errorDescription": "Only moderators can force unpublish other participants' tracks",
			})
			return
		}
	}
	if debug {
		log.Println("Unpublishing track:", map[string]interface{}{"roomId": roomId, "sessionId": sessionId, "trackName": req.TrackName, "mid": req.Mid})
	}

	if req.Mid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errorCode":        "INVALID_REQUEST",
			"errorDescription": "mid is required to unpublish a track.",
		})
		return
	}

	if req.SessionDescription == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errorCode":        "INVALID_REQUEST",
			"errorDescription": "sessionDescription is required to unpublish a track.",
		})
		return
	}

	cfUrl := fmt.Sprintf("%s/sessions/%s/tracks/close", cloudflareBasePath, sessionId)
	if debug {
		log.Println("Calling Cloudflare API:", cfUrl)
	}

	requestBody := map[string]interface{}{
		"tracks": []map[string]string{
			{"mid": req.Mid},
		},
		"force":              req.Force,
		"sessionDescription": req.SessionDescription,
	}
	if debug {
		log.Printf("Request body: %+v\n", requestBody) // Use %+v for detailed printing
	}

	data, err := unpublishToCloudflare(cfUrl, requestBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if debug {
		log.Println("Cloudflare API response:", data)
	}
	broadcastToRoom(roomId, gin.H{
		"type":    "track-unpublished",
		"payload": gin.H{"sessionId": sessionId, "trackName": req.TrackName},
	}, sessionId)

	c.JSON(http.StatusOK, data)

}

func pullTracks(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")

	// Struct to hold request body, khớp với frontend JavaScript (_pullTracks)
	var req struct {
		RemoteSessionId string `json:"remoteSessionId"` // camelCase, khớp với frontend
		TrackName       string `json:"trackName"`       // Kéo từng track một
	}

	// Bind JSON request body từ request Gin
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Lấy thông tin room từ bộ nhớ
	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}

	participant := findParticipantBySessionId(room, sessionId)
	if participant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found in this room"})
		return
	}

	// Tạo cấu trúc tracksToPull cho Cloudflare API (kéo 1 track)
	tracksToPull := []map[string]interface{}{
		{
			"location":  "remote",
			"sessionId": req.RemoteSessionId, // Dùng RemoteSessionId từ request struct
			"trackName": req.TrackName,       // Dùng TrackName từ request struct
		},
	}

	// Gọi Cloudflare API để pull track (dùng hàm makeCloudflareRequest helper)
	url := fmt.Sprintf("%s/sessions/%s/tracks/new", cloudflareBasePath, sessionId)
	requestBody := map[string]interface{}{
		"tracks": tracksToPull,
	}

	// Gọi makeCloudflareRequest để thực hiện request đến Cloudflare API
	data, err, statusCode := makeCloudflareRequest("POST", url, requestBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to pull track", "detail": err.Error()})
		return
	}
	// Kiểm tra mã trạng thái lỗi từ Cloudflare API
	if statusCode >= 400 {
		c.JSON(statusCode, gin.H{"error": "Cloudflare API error during pull track", "detail": data})
		return
	}

	// Trả về phản hồi từ Cloudflare API cho frontend
	c.JSON(http.StatusOK, data)
}

// Helper function để tìm participant theo sessionId (tái sử dụng từ code của bạn)
func findParticipantBySessionId(room *Room, sessionId string) *Participant {
	room.RLock()
	defer room.RUnlock()
	for _, p := range room.Participants {
		if p.SessionID == sessionId {
			return p
		}
	}
	return nil
}

func renegotiateSession(c *gin.Context) {
	sessionId := c.Param("sessionId")
	var req struct {
		SDP     string `json:"sdp"`
		SDPType string `json:"type"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sdp := req.SDP
	sdpType := req.SDPType
	// var req struct {
	// 	SessionDescription struct {
	// 		SDP  string `json:"sdp"`
	// 		Type string `json:"type"`
	// 	} `json:"sessionDescription"`
	// }

	// if err := c.ShouldBindJSON(&req); err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 	return
	// }

	body := map[string]interface{}{
		"sessionDescription": map[string]string{
			"sdp":  sdp,
			"type": sdpType,
		},
	}

	data, err := renegotiateWithCloudflare(sessionId, body)
	if err != nil {
		if data != nil && data["errorCode"] != nil { // Check for Cloudflare error
			c.JSON(http.StatusBadRequest, data)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, data)
}

func manageDataChannels(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")

	rooms.RLock()
	room, ok := rooms.m[roomId]
	print(room)
	rooms.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}
	var req struct {
		DataChannels []struct {
			Location        string `json:"location"`
			DataChannelName string `json:"dataChannelName"`
		} `json:"dataChannels"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfUrl := fmt.Sprintf("%s/sessions/%s/datachannels/new", cloudflareBasePath, sessionId)
	dataChannels := make([]map[string]interface{}, len(req.DataChannels))
	for i, dc := range req.DataChannels {
		dataChannels[i] = map[string]interface{}{
			"location":        dc.Location,
			"dataChannelName": dc.DataChannelName,
		}
	}

	data, err := manageDataChannelsWithCloudflare(cfUrl, dataChannels)
	if err != nil {
		if data != nil && data["errorCode"] != nil { // Check for Cloudflare error
			c.JSON(http.StatusBadRequest, data)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	//Optionally, if the user is publishing a channel, you could record that in `participant.publishedDataChannels` in memory
	for _, dc := range req.DataChannels {
		if dc.Location == "local" {
			// E.g. store in participant.publishedDataChannels = append(participant.publishedDataChannels, dc.DataChannelName)
		}
	}
	c.JSON(http.StatusOK, data)
}

func getParticipants(c *gin.Context) {
	roomId := c.Param("roomId")

	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"participants": room.Participants})
}

func getParticipantTracks(c *gin.Context) {
	sessionId := c.Param("sessionId")
	roomId := c.Param("roomId")

	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}
	var participant *Participant
	room.RLock()
	for _, p := range room.Participants {
		if p.SessionID == sessionId {
			participant = p
			break
		}
	}
	room.RUnlock()

	if participant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Participant not found"})
		return
	}

	c.JSON(http.StatusOK, participant.PublishedTracks)
}

func getICEServers(c *gin.Context) {
	cloudflareTurnID := os.Getenv("CLOUDFLARE_TURN_ID")
	cloudflareTurnToken := os.Getenv("CLOUDFLARE_TURN_TOKEN")

	if cloudflareTurnID == "" || cloudflareTurnToken == "" {
		c.JSON(http.StatusOK, gin.H{
			"iceServers": []gin.H{
				{"urls": "stun:stun.cloudflare.com:3478"},
			},
		})
		return
	}

	lifetime := 600 // Credentials valid for 10 minutes (600 seconds)
	timestamp := time.Now().Unix() + int64(lifetime)
	username := fmt.Sprintf("%d:%s", timestamp, cloudflareTurnID)

	// Create HMAC-SHA256 hash using CLOUDFLARE_TURN_TOKEN as the key
	h := hmac.New(sha256.New, []byte(cloudflareTurnToken))
	h.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(h.Sum(nil))

	iceServers := gin.H{
		"iceServers": []gin.H{
			{"urls": "stun:stun.cloudflare.com:3478"},
			{
				"urls":       "turn:turn.cloudflare.com:3478?transport=udp",
				"username":   username,
				"credential": credential,
			},
			{
				"urls":       "turn:turn.cloudflare.com:3478?transport=tcp",
				"username":   username,
				"credential": credential,
			},
			{
				"urls":       "turns:turn.cloudflare.com:5349?transport=tcp",
				"username":   username,
				"credential": credential,
			},
		},
	}

	c.JSON(http.StatusOK, iceServers)
}
func getToken(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId := uuid.NewString()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":      userId,
		"username":    req.Username,
		"role":        "demo",
		"isModerator": true, // This should come from a database in production
		"exp":         time.Now().Add(time.Hour * 8).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}
	// Store initial user info
	users.Lock()
	users.m[userId] = &User{
		UserID:      userId,
		Username:    req.Username,
		IsModerator: true,
		Role:        "demo",
	}
	users.Unlock()

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func getSessionState(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")
	_ = roomId

	data, err := getSessionStateFromCloudflare(sessionId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errorCode":        "SESSION_STATE_ERROR",
			"errorDescription": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, data)
}

func getUserInfo(c *gin.Context) {
	userIdParam := c.Param("userId")
	user, _ := c.Get("user")
	currentUser, ok := user.(*User)
	if !ok {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid user"})
		return
	}

	if userIdParam == "me" {
		users.RLock()
		userInfo, ok := users.m[currentUser.UserID]
		users.RUnlock()
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{
				"errorCode":        "USER_NOT_FOUND",
				"errorDescription": "Current user not found",
			})
			return
		}
		c.JSON(http.StatusOK, userInfo)
		return
	}

	users.RLock()
	requestedUser, ok := users.m[userIdParam]
	users.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"errorCode":        "USER_NOT_FOUND",
			"errorDescription": "User not found",
		})
		return
	}

	// Return limited info for other users
	c.JSON(http.StatusOK, gin.H{
		"userId":   requestedUser.UserID,
		"username": requestedUser.Username,
	})
}

func leaveRoom(c *gin.Context) {
	roomId := c.Param("roomId")
	var req struct {
		SessionId string `json:"sessionId"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}

	participantIndex := -1
	var participant *Participant
	room.Lock()
	for i, p := range room.Participants {
		if p.SessionID == req.SessionId {
			participantIndex = i
			participant = p
			break
		}
	}

	if participantIndex != -1 {

		room.Participants = append(room.Participants[:participantIndex], room.Participants[participantIndex+1:]...)
		// Notify other participants about the leave
		broadcastToRoom(roomId, gin.H{
			"type": "participant-left",
			"payload": gin.H{
				"sessionId": req.SessionId,
				"userId":    participant.UserID,
			},
		}, req.SessionId)
		// If room is empty, delete it
		if len(room.Participants) == 0 {
			rooms.Lock()
			delete(rooms.m, roomId)
			rooms.Unlock()
		}
	}
	room.Unlock()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func updateTrackStatus(c *gin.Context) {
	roomId := c.Param("roomId")
	sessionId := c.Param("sessionId")
	user, _ := c.Get("user")
	currentUser, ok := user.(*User)
	if !ok {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden: Invalid user"})
		return
	}

	var req struct {
		TrackId string `json:"trackId"`
		Kind    string `json:"kind"`
		Enabled bool   `json:"enabled"`
		Force   bool   `json:"force"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// If trying to force change someone else's track
	if req.Force && sessionId != currentUser.UserID {
		if !currentUser.IsModerator {
			c.JSON(http.StatusForbidden, gin.H{
				"errorCode":        "NOT_AUTHORIZED",
				"errorDescription": "Only moderators can force change other participants' tracks",
			})
			return
		}
	}

	// Notify other participants about the track status change
	broadcastToRoom(roomId, gin.H{
		"type": "track-status-changed",
		"payload": gin.H{
			"sessionId": sessionId,
			"trackId":   req.TrackId,
			"kind":      req.Kind,
			"enabled":   req.Enabled,
		},
	}, sessionId)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func getRooms(c *gin.Context) {
	rooms.RLock()
	roomList := make([]gin.H, 0, len(rooms.m))
	for roomId, room := range rooms.m {
		roomList = append(roomList, serializeRoom(roomId, room))
	}
	rooms.RUnlock()
	c.JSON(http.StatusOK, gin.H{"rooms": roomList})
}

func updateRoomMetadata(c *gin.Context) {
	roomId := c.Param("roomId")
	var req struct {
		Name     string                 `json:"name"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rooms.RLock()
	room, ok := rooms.m[roomId]
	rooms.RUnlock()

	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}
	room.Lock()
	if req.Name != "" {
		room.Name = req.Name
	}

	if req.Metadata != nil {
		if room.Metadata == nil {
			room.Metadata = make(map[string]interface{})
		}
		for k, v := range req.Metadata {
			room.Metadata[k] = v
		}
	}
	room.Unlock()

	// Notify room participants about the update
	broadcastToRoom(roomId, gin.H{
		"type": "room-metadata-updated",
		"payload": gin.H{
			"roomId":   roomId,
			"name":     room.Name,
			"metadata": room.Metadata,
		},
		"from": "server",
	}, "") // Empty string means no user is excluded from the broadcast

	c.JSON(http.StatusOK, serializeRoom(roomId, room))
}

// --- WebSocket Handling ---

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Cẩn thận với setting này trong production
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func websocketHandler(c *gin.Context) {
	if debug {
		log.Printf("Incoming WebSocket request from: %s\n", c.Request.RemoteAddr)
	}

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v\n", err)
		return
	}
	defer ws.Close()

	handleWebSocket(ws)
}

func handleWebSocket(ws *websocket.Conn) {
	if debug {
		log.Printf("New WebSocket connection established from: %s\n", ws.RemoteAddr().String())
	}
	defer ws.Close()

	var userId string
	var roomId string

	for {
		// Đọc message
		messageType, message, err := ws.ReadMessage()
		log.Println("messageType", messageType)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			handleWSDisconnect(ws, roomId, userId)
			break
		}

		// Parse message
		var data map[string]interface{}
		if err := json.Unmarshal(message, &data); err != nil {
			log.Println("Error parsing message:", err)
			continue
		}

		messageTypeStr, ok := data["type"].(string)
		if !ok {
			log.Println("Invalid message format: missing or invalid 'type'")
			continue
		}

		switch messageTypeStr {
		case "join-websocket":
			// Format payload giống Express
			payload := map[string]interface{}{
				"roomId": data["payload"].(map[string]interface{})["roomId"],
				"userId": data["payload"].(map[string]interface{})["userId"],
				"token":  data["payload"].(map[string]interface{})["token"],
			}
			handleWSJoin(ws, payload)

		case "data-message":
			// Format payload giống Express
			payload := map[string]interface{}{
				"from": data["payload"].(map[string]interface{})["from"],
				"data": data["payload"].(map[string]interface{})["message"],
			}
			handleDataMessage(ws, payload)

		default:
			log.Println("Unknown message type:", messageTypeStr)
		}
	}
}

// --- WebSocket Helper Functions ---

func getRoomIdByUserId(userId string) string {
	rooms.RLock()
	defer rooms.RUnlock()
	for roomId, room := range rooms.m {
		for _, p := range room.Participants {
			if p.UserID == userId {
				return roomId
			}
		}
	}
	return ""
}

func getRoomIdBySessionId(sessionId string) string {
	rooms.RLock()
	defer rooms.RUnlock()
	for roomId, room := range rooms.m {
		for _, p := range room.Participants {
			if p.SessionID == sessionId {
				return roomId
			}
		}
	}
	return ""
}

func getWebSocketByUserId(userId string) *websocket.Conn {
	wsConnections.RLock()
	defer wsConnections.RUnlock()
	for _, userMap := range wsConnections.m {
		if conn, ok := userMap[userId]; ok {
			return conn
		}
	}
	return nil
}

func handleWSJoin(ws *websocket.Conn, payload map[string]interface{}) {
	roomId, ok1 := payload["roomId"].(string)
	userId, ok2 := payload["userId"].(string)
	token, ok3 := payload["token"].(string)
	//check roomid, userid and token
	if !ok1 || !ok2 || (authRequired && !ok3) {
		log.Println("Missing roomId, userId, or token in WS join")
		_ = ws.WriteJSON(map[string]string{"error": "Missing roomId, userId, or token"})
		return
	}
	if authRequired {
		_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secretKey), nil
		})
		if err != nil {
			log.Println("Invalid token in WS join:", err)
			_ = ws.WriteJSON(map[string]string{"error": "Invalid or expired token"})
			return
		}
	}

	// Add user to the room's WebSocket connections
	wsConnections.Lock()
	if _, ok := wsConnections.m[roomId]; !ok {
		wsConnections.m[roomId] = make(map[string]*websocket.Conn)
	}
	wsConnections.m[roomId][userId] = ws
	wsConnections.Unlock()

	if debug {
		log.Printf("User %s joined room %s via WS\n", userId, roomId)
	}
	response := map[string]string{"message": "Joined room successfully"}
	if err := ws.WriteJSON(response); err != nil {
		log.Println("Error sending join response:", err)
	}
}

func handleDataMessage(ws *websocket.Conn, payload map[string]interface{}) {
	from, ok1 := payload["from"].(string)
	data, ok2 := payload["data"] //  "data", not "message"

	if !ok1 || !ok2 {
		log.Println("Invalid data-message payload:", payload)
		return
	}

	// Get room ID from the session ID.  Crucially, this now uses *session* ID.
	roomId := getRoomIdBySessionId(from)
	if roomId == "" {
		log.Printf("Room not found for session: %s\n", from)
		return
	}

	// Broadcast to all participants in the room except the sender
	broadcastToRoom(roomId, gin.H{
		"type": "data-message",
		"payload": gin.H{
			"from": from,
			"data": data, //  "data", not "message"
		},
	}, from) // Exclude the sender
}

func handleWSDisconnect(ws *websocket.Conn, roomId string, userId string) {
	wsConnections.Lock()
	defer wsConnections.Unlock()
	//remove user from room
	if _, ok := wsConnections.m[roomId]; ok {
		delete(wsConnections.m[roomId], userId)
		if debug {
			log.Printf("User %s disconnected from room %s\n", userId, roomId)
		}
	}
}

func broadcastToRoom(roomId string, message gin.H, excludeUserId string) {
	if debug {
		log.Printf("Broadcasting to room %s: %+v (excluding: %s)\n", roomId, message, excludeUserId)
	}
	rooms.RLock()
	_, ok := rooms.m[roomId]
	rooms.RUnlock()
	if !ok {
		log.Printf("Room %s not found for broadcast\n", roomId)
		return
	}

	wsConnections.RLock()
	connections, ok := wsConnections.m[roomId]
	wsConnections.RUnlock()
	if !ok {
		log.Printf("No WebSocket connections found for room %s\n", roomId)
		return
	}

	// Serialize message once
	msgBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error serializing broadcast message: %v\n", err)
		return
	}

	if debug {
		log.Printf("Serialized message for broadcast: %s\n", string(msgBytes))
	}

	wsConnections.RLock()
	defer wsConnections.RUnlock()

	for userId, conn := range connections {
		if userId == excludeUserId {
			continue
		}
		if conn != nil {
			err := conn.WriteMessage(websocket.TextMessage, msgBytes)
			if err != nil {
				log.Printf("Error broadcasting to user %s: %v\n", userId, err)
				// Clean up failed connection
				wsConnections.Lock()
				delete(wsConnections.m[roomId], userId)
				wsConnections.Unlock()
			} else if debug {
				log.Printf("Successfully sent broadcast message to user: %s\n", userId)
			}
		}
	}
}

func main() {
	initConfig() // Initialize configuration

	r := gin.Default()

	// CORS middleware (configure as needed)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // For development only!
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Upgrade, Connection")
		c.Writer.Header().Set("Access-Control-Max-Age", "3600")

		// Handle WebSocket pre-flight
		if c.Request.Method == "OPTIONS" {
			if c.Request.Header.Get("Upgrade") == "websocket" {
				c.Writer.Header().Set("Connection", "Upgrade")
				c.Writer.Header().Set("Upgrade", "websocket")
			}
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// r.POST("/auth/token", getToken)
	// // Protected routes (require JWT)
	// api := r.Group("/api", verifyToken)
	// {
	// 	// Match Express routes
	// 	api.POST("/rooms", createRoom)
	// 	api.GET("/rooms", getRooms)
	// 	api.GET("/inspect-rooms", inspectRooms)
	// 	api.POST("/rooms/:roomId/join", joinRoom)
	// 	api.POST("/rooms/:roomId/sessions/:sessionId/publish", publishTracks)
	// 	api.POST("/rooms/:roomId/sessions/:sessionId/unpublish", unpublishTrack)
	// 	api.POST("/rooms/:roomId/sessions/:sessionId/pull", pullTracks)
	// 	api.PUT("/rooms/:roomId/sessions/:sessionId/renegotiate", renegotiateSession)
	// 	api.POST("/rooms/:roomId/sessions/:sessionId/datachannels/new", manageDataChannels)
	// 	api.GET("/rooms/:roomId/participants", getParticipants)
	// 	api.GET("/rooms/:roomId/participant/:sessionId/tracks", getParticipantTracks)
	// 	api.GET("/ice-servers", getICEServers)
	// 	api.GET("/rooms/:roomId/sessions/:sessionId/state", getSessionState)
	// 	api.GET("/users/:userId", getUserInfo)
	// 	api.POST("/rooms/:roomId/leave", leaveRoom)
	// 	api.POST("/rooms/:roomId/sessions/:sessionId/track-status", updateTrackStatus)
	// 	api.PUT("/rooms/:roomId/metadata", updateRoomMetadata)
	// }

	r.GET("/ws", websocketHandler)

	// Start the server
	log.Printf("Server listening on http://localhost:%s\n", port)

	//listen and serve for http
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
