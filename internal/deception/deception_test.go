package deception

import "testing"

func TestGeneratedCardsAreLuhnValid(t *testing.T) {
	cards := GenerateCards(200, 99)
	if len(cards) != 200 {
		t.Fatalf("expected 200 cards, got %d", len(cards))
	}
	for _, card := range cards {
		if !luhnValid(card.PrimaryAccount) {
			t.Fatalf("card %s is not Luhn-valid", card.PrimaryAccount)
		}
	}
}

func TestGeneratorsAreDeterministic(t *testing.T) {
	first := GenerateAccounts(10, 7)
	second := GenerateAccounts(10, 7)
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("accounts not deterministic at %d", index)
		}
	}
}

func luhnValid(number string) bool {
	sum := 0
	double := false
	for position := len(number) - 1; position >= 0; position-- {
		digit := int(number[position] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}
