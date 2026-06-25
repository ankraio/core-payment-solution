package deception

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type Card struct {
	HolderName     string `json:"holder_name"`
	PrimaryAccount string `json:"pan"`
	Expiry         string `json:"expiry"`
	Brand          string `json:"brand"`
	Token          string `json:"network_token"`
}

type Account struct {
	AccountID   string  `json:"account_id"`
	MerchantID  string  `json:"merchant_id"`
	HolderName  string  `json:"holder_name"`
	Email       string  `json:"email"`
	Balance     float64 `json:"balance_minor_units"`
	Currency    string  `json:"currency"`
	IBAN        string  `json:"iban"`
	Status      string  `json:"status"`
	LastFourPAN string  `json:"last_four_pan"`
}

type Transaction struct {
	TransactionID string    `json:"transaction_id"`
	AccountID     string    `json:"account_id"`
	AmountMinor   int64     `json:"amount_minor"`
	Currency      string    `json:"currency"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	Descriptor    string    `json:"descriptor"`
}

var firstNames = []string{"Olivia", "Liam", "Emma", "Noah", "Ava", "Sofia", "Mateo", "Yuki", "Aanya", "Lucas", "Ingrid", "Hassan", "Mei", "Diego", "Freya"}
var lastNames = []string{"Andersson", "Okafor", "Nakamura", "Petrov", "Silva", "Kowalski", "Haddad", "Bianchi", "Lindqvist", "Mwangi", "Schmidt", "Tanaka", "Rossi", "Novak", "Bergstrom"}
var currencies = []string{"USD", "EUR", "SEK", "GBP", "JPY"}
var brands = []string{"VISA", "MASTERCARD", "AMEX"}
var descriptors = []string{"SUBSCRIPTION RENEWAL", "POS PURCHASE", "REFUND", "PAYOUT", "CHARGEBACK", "TOPUP", "INVOICE SETTLEMENT"}

func luhnComplete(prefix string, length int, source *rand.Rand) string {
	digits := make([]int, 0, length)
	for _, character := range prefix {
		digits = append(digits, int(character-'0'))
	}
	for len(digits) < length-1 {
		digits = append(digits, source.Intn(10))
	}
	sum := 0
	double := true
	for position := len(digits) - 1; position >= 0; position-- {
		value := digits[position]
		if double {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
		double = !double
	}
	check := (10 - (sum % 10)) % 10
	digits = append(digits, check)
	var builder strings.Builder
	for _, digit := range digits {
		builder.WriteString(fmt.Sprintf("%d", digit))
	}
	return builder.String()
}

func GenerateCards(count int, seed int64) []Card {
	source := rand.New(rand.NewSource(seed))
	cards := make([]Card, 0, count)
	for index := 0; index < count; index++ {
		brand := brands[source.Intn(len(brands))]
		var prefix string
		var length int
		switch brand {
		case "VISA":
			prefix, length = "411111", 16
		case "MASTERCARD":
			prefix, length = "555555", 16
		default:
			prefix, length = "378282", 15
		}
		pan := luhnComplete(prefix, length, source)
		cards = append(cards, Card{
			HolderName:     randomName(source),
			PrimaryAccount: pan,
			Expiry:         fmt.Sprintf("%02d/%02d", 1+source.Intn(12), 27+source.Intn(5)),
			Brand:          brand,
			Token:          "tok_" + randomHex(source, 24),
		})
	}
	return cards
}

func GenerateAccounts(count int, seed int64) []Account {
	source := rand.New(rand.NewSource(seed + 7))
	accounts := make([]Account, 0, count)
	for index := 0; index < count; index++ {
		currency := currencies[source.Intn(len(currencies))]
		accounts = append(accounts, Account{
			AccountID:   fmt.Sprintf("acct_%s", randomHex(source, 16)),
			MerchantID:  fmt.Sprintf("merch_%s", randomHex(source, 10)),
			HolderName:  randomName(source),
			Email:       randomEmail(source),
			Balance:     float64(source.Intn(9_000_000)) + float64(source.Intn(100)),
			Currency:    currency,
			IBAN:        randomIBAN(source),
			Status:      pick(source, "active", "active", "active", "frozen", "review"),
			LastFourPAN: fmt.Sprintf("%04d", source.Intn(10000)),
		})
	}
	return accounts
}

func GenerateTransactions(accounts []Account, perAccount int, seed int64) []Transaction {
	source := rand.New(rand.NewSource(seed + 13))
	transactions := make([]Transaction, 0, len(accounts)*perAccount)
	now := time.Now().UTC()
	for _, account := range accounts {
		for index := 0; index < perAccount; index++ {
			transactions = append(transactions, Transaction{
				TransactionID: fmt.Sprintf("txn_%s", randomHex(source, 18)),
				AccountID:     account.AccountID,
				AmountMinor:   int64(source.Intn(500000) + 100),
				Currency:      account.Currency,
				Status:        pick(source, "captured", "captured", "authorized", "refunded", "failed"),
				CreatedAt:     now.Add(-time.Duration(source.Intn(720)) * time.Hour),
				Descriptor:    descriptors[source.Intn(len(descriptors))],
			})
		}
	}
	return transactions
}

func randomName(source *rand.Rand) string {
	return firstNames[source.Intn(len(firstNames))] + " " + lastNames[source.Intn(len(lastNames))]
}

func randomEmail(source *rand.Rand) string {
	return fmt.Sprintf("%s.%s@example-merchant.test",
		strings.ToLower(firstNames[source.Intn(len(firstNames))]),
		strings.ToLower(lastNames[source.Intn(len(lastNames))]))
}

func randomIBAN(source *rand.Rand) string {
	return fmt.Sprintf("SE%02d%04d%016d", source.Intn(100), 8000+source.Intn(2000), source.Int63n(1_000_000_000_000_0000))
}

func randomHex(source *rand.Rand, length int) string {
	const alphabet = "0123456789abcdef"
	builder := make([]byte, length)
	for index := range builder {
		builder[index] = alphabet[source.Intn(len(alphabet))]
	}
	return string(builder)
}

func pick(source *rand.Rand, options ...string) string {
	return options[source.Intn(len(options))]
}
