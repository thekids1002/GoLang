package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"bytes"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Smart Contract & Cloudflare Config
const (
	infuraURL          = "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
	contractAddress    = "0xYourSmartContractAddress"
	cloudflareBasePath = "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/calls"
	cloudflareAuth     = "Bearer YOUR_CLOUDFLARE_API_TOKEN"
	privateKeyHex      = "YOUR_WALLET_PRIVATE_KEY"
)

// ABI của Smart Contract
const contractABI = `[{"anonymous":false,"inputs":[{"indexed":false,"name":"roomId","type":"bytes32"},{"indexed":false,"name":"user","type":"address"},{"indexed":false,"name":"offer","type":"string"},{"indexed":false,"name":"tracks","type":"tuple[]"}],"name":"RequestTrackPublish","type":"event"}]`

func main() {
	client, err := ethclient.Dial(infuraURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	contractABIParsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}

	contractAddr := common.HexToAddress(contractAddress)
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddr},
	}

	logs := make(chan ethereum.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatalf("Failed to subscribe to logs: %v", err)
	}

	fmt.Println("Listening for smart contract events...")
	for logEntry := range logs {
		event, err := contractABIParsed.EventByID(logEntry.Topics[0])
		if err != nil {
			log.Printf("Unknown event: %v\n", err)
			continue
		}

		switch event.Name {
		case "RequestTrackPublish":
			handleTrackPublish(client, logEntry, contractABIParsed)
		case "RequestTrackUnpublish":
			handleTrackUnpublish(client, logEntry, contractABIParsed)
		case "RequestTrackPull":
			handleTrackPull(client, logEntry, contractABIParsed)
		case "RequestSessionRenegotiation":
			handleRenegotiateSession(client, logEntry, contractABIParsed)
		case "RequestManageDataChannels":
			handleManageDataChannels(client, logEntry, contractABIParsed)
		case "RequestSessionState":
			handleSessionState(client, logEntry, contractABIParsed)
		default:
			log.Printf("Unhandled event: %s\n", event.Name)
		}
	}
}

// Gọi Cloudflare API
func callCloudflareAPI(endpoint string, requestBody map[string]interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/%s", cloudflareBasePath, endpoint)
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", cloudflareAuth)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	return data, nil
}

// Kết nối với Smart Contract để cập nhật trạng thái
func updateSmartContract(functionName string, params ...interface{}) error {
	// Kết nối Ethereum
	client, err := ethclient.Dial(infuraURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Ethereum client: %v", err)
	}
	defer client.Close()

	// Parse Private Key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %v", err)
	}

	// Lấy địa chỉ ví của người gửi
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKey)

	// Lấy nonce (số giao dịch của ví)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %v", err)
	}

	// Lấy gas price hiện tại
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get gas price: %v", err)
	}

	// Lấy Chain ID (Mainnet, Testnet, v.v.)
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %v", err)
	}

	// Load Smart Contract ABI
	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	// Encode dữ liệu giao dịch (tạo input cho Smart Contract)
	inputData, err := parsedABI.Pack(functionName, params...)
	if err != nil {
		return fmt.Errorf("failed to pack function call: %v", err)
	}

	// Tạo giao dịch
	toAddress := common.HexToAddress(contractAddress)
	gasLimit := uint64(200000) // Giới hạn gas

	tx := types.NewTransaction(nonce, toAddress, big.NewInt(0), gasLimit, gasPrice, inputData)

	// Ký giao dịch với Private Key
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Gửi giao dịch lên Ethereum
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	txHash := signedTx.Hash().Hex()
	fmt.Printf("Transaction sent! Tx Hash: %s\n", txHash)

	return nil
}

// Xử lý sự kiện publish track
func handleTrackPublish(client *ethclient.Client, log ethereum.Log, contractABI abi.ABI) {
	var event struct {
		RoomId string `json:"roomId"`
		User   string `json:"user"`
		Offer  string `json:"offer"`
		Tracks []struct {
			TrackName string `json:"trackName"`
			Mid       string `json:"mid"`
			Location  string `json:"location"`
		} `json:"tracks"`
	}

	err := contractABI.UnpackIntoInterface(&event, "RequestTrackPublish", log.Data)
	if err != nil {
		log.Printf("Failed to unpack event: %v\n", err)
		return
	}

	requestBody := map[string]interface{}{
		"sessionDescription": event.Offer,
		"tracks":             event.Tracks,
	}
	response, err := callCloudflareAPI(fmt.Sprintf("sessions/%s/tracks/new", event.RoomId), requestBody)
	if err != nil {
		log.Printf("Cloudflare API error: %v\n", err)
		return
	}

	err = updateSmartContract("processTrackPublish", event.RoomId, event.User, extractTrackNames(event.Tracks), response["sessionDescription"])
	if err != nil {
		log.Printf("Failed to update smart contract: %v\n", err)
	}
}

// Xử lý sự kiện unpublish track
func handleTrackUnpublish(client *ethclient.Client, log ethereum.Log, contractABI abi.ABI) {
	var event struct {
		RoomId string `json:"roomId"`
		User   string `json:"user"`
		TrackName string `json:"trackName"`
		Mid    string `json:"mid"`
		Force  bool   `json:"force"`
		SessionDescription string `json:"sessionDescription"`
	}

	err := contractABI.UnpackIntoInterface(&event, "RequestTrackUnpublish", log.Data)
	if err != nil {
		log.Printf("Failed to unpack event: %v\n", err)
		return
	}

	requestBody := map[string]interface{}{
		"tracks": []map[string]string{
			{"mid": event.Mid},
		},
		"force": event.Force,
		"sessionDescription": event.SessionDescription,
	}
	response, err := callCloudflareAPI(fmt.Sprintf("sessions/%s/tracks/close", event.RoomId), requestBody)
	if err != nil {
		log.Printf("Cloudflare API error: %v\n", err)
		return
	}

	err = updateSmartContract("confirmTrackUnpublish", event.RoomId, event.User, event.TrackName, response["sessionDescription"])
	if err != nil {
		log.Printf("Failed to update smart contract: %v\n", err)
	}
}

// Trích xuất danh sách track names
func extractTrackNames(tracks []struct {
	TrackName string `json:"trackName"`
	Mid       string `json:"mid"`
	Location  string `json:"location"`
}) []string {
	names := make([]string, len(tracks))
	for i, t := range tracks {
		names[i] = t.TrackName
	}
	return names
}
