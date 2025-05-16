package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

// --- Structs for Request Binding ---
type CipherRequest struct {
	Text      string `form:"text" binding:"required"`
	Key       string `form:"key"`
	Operation string `form:"operation" binding:"required"` // "encrypt" or "decrypt"
	KeyInt    int    `form:"key_int"`                      // For railfence, Caesar shift
}

type MultiLayerRequest struct {
	Text        string   `form:"text" binding:"required"`
	Ciphers     []string `form:"ciphers[]" binding:"required"`
	Keys        []string `form:"keys[]" binding:"required"`
	KeyInts     []string `form:"key_ints[]"` // String representations of integers for keys like Caesar shift or Railfence rails
	Operation   string   `form:"operation" binding:"required"`
	CipherCount int      `form:"cipher_count"`
}

// --- Global Variables / Constants ---
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// var tmpl *template.Template // Not needed if using Gin's LoadHTMLGlob with FuncMap

// --- Helper Functions ---

// prepareText cleans text: uppercase, remove non-alpha for ciphers that need it.
func prepareText(text string, keepNonAlpha bool) string {
	var result strings.Builder
	text = strings.ToUpper(text)
	for _, r := range text {
		if unicode.IsLetter(r) {
			result.WriteRune(r)
		} else if keepNonAlpha {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// --- Caesar Cipher ---
func caesar(text string, shift int, encrypt bool) string {
	shift = shift % 26
	if !encrypt {
		shift = -shift
	}
	var result string
	for i := 0; i < len(text); i++ {
		if text[i] >= 'A' && text[i] <= 'Z' {
			result += string((int(text[i])-65+shift)%26 + 65)
		} else if text[i] >= 'a' && text[i] <= 'z' {
			result += string((int(text[i])-97+shift)%26 + 97)
		} else {
			result += string(text[i])
		}
	}
	return result
}

// --- Vigenere Cipher ---
func vigenere(text string, key string, encrypt bool) string {
	if key == "" {
		return text // No key, no change
	}
	key = prepareText(key, false) // Key must be letters only
	if len(key) == 0 {
		return text
	}
	keyIndex := 0
	var result strings.Builder
	for _, r := range text {
		if r >= 'A' && r <= 'Z' {
			keyChar := rune(key[keyIndex%len(key)])
			shift := int(keyChar - 'A')
			if !encrypt {
				shift = -shift
			}

			finalChar := rune((int(r-'A')+shift+26)%26 + 'A')
			result.WriteRune(finalChar)
			keyIndex++
		} else {
			result.WriteRune(r) // Keep non-alphabetic characters
		}
	}
	return result.String()
}

// --- Monoalphabetic Cipher ---
// generateMonoKey creates a monoalphabetic key from a keyword
func generateMonoKey(keyword string) string {
	keyword = prepareText(keyword, false)
	var keyTable strings.Builder
	seen := make(map[rune]bool)

	for _, r := range keyword {
		if !seen[r] {
			keyTable.WriteRune(r)
			seen[r] = true
		}
	}
	for _, r := range alphabet {
		if !seen[r] {
			keyTable.WriteRune(r)
			seen[r] = true
		}
	}
	return keyTable.String()
}

func monoalphabetic(text string, key string, encrypt bool) string {
	monoKey := generateMonoKey(key)
	if len(monoKey) != 26 {
		return "Error: Invalid key for monoalphabetic cipher (must result in a 26-char permutation)."
	}

	var result strings.Builder
	srcAlphabet := alphabet
	destAlphabet := monoKey

	if !encrypt {
		srcAlphabet, destAlphabet = destAlphabet, srcAlphabet
	}

	mapping := make(map[rune]rune)
	for i, r := range srcAlphabet {
		mapping[r] = rune(destAlphabet[i])
	}

	for _, r := range text {
		if mappedChar, ok := mapping[r]; ok {
			result.WriteRune(mappedChar)
		} else {
			result.WriteRune(r) // Keep non-alphabetic characters
		}
	}
	return result.String()
}

// --- Rail Fence Cipher ---
func railfenceEncrypt(text string, rails int) string {
	if rails <= 1 {
		return text
	}
	text = prepareText(text, true) // Keep non-alpha for railfence structure
	fence := make([][]rune, rails)
	for i := range fence {
		fence[i] = make([]rune, 0)
	}

	rail := 0
	direction := 1 // 1 for down, -1 for up

	for _, char := range text {
		fence[rail] = append(fence[rail], char)
		if rail == 0 {
			direction = 1
		} else if rail == rails-1 {
			direction = -1
		}
		rail += direction
	}

	var encryptedText strings.Builder
	for _, r := range fence {
		for _, char := range r {
			encryptedText.WriteRune(char)
		}
	}
	return encryptedText.String()
}

func railfenceDecrypt(cipherText string, rails int) string {
	if rails <= 1 {
		return cipherText
	}
	cipherText = prepareText(cipherText, true)
	textLen := len(cipherText)
	fence := make([][]rune, rails)
	for i := range fence {
		fence[i] = make([]rune, textLen) // Max possible length
	}

	railSizes := make([]int, rails)
	rail := 0
	direction := 1
	for i := 0; i < textLen; i++ {
		railSizes[rail]++
		if rail == 0 {
			direction = 1
		} else if rail == rails-1 {
			direction = -1
		}
		rail += direction
	}

	idx := 0
	for r := 0; r < rails; r++ {
		for c := 0; c < railSizes[r]; c++ {
			fence[r][c] = rune(cipherText[idx])
			idx++
		}
	}

	var decryptedText strings.Builder
	currentRailPositions := make([]int, rails)
	rail = 0
	direction = 1
	for i := 0; i < textLen; i++ {
		decryptedText.WriteRune(fence[rail][currentRailPositions[rail]])
		currentRailPositions[rail]++
		if rail == 0 {
			direction = 1
		} else if rail == rails-1 {
			direction = -1
		}
		rail += direction
	}
	return decryptedText.String()
}

// --- Row Transposition Cipher ---
// parseRowTranspositionKey converts "3-1-4-2" to []int{2,0,3,1} (0-indexed)
func parseRowTranspositionKey(keyStr string) ([]int, error) {
	parts := strings.Split(keyStr, "-")
	key := make([]int, len(parts))
	seen := make(map[int]bool) // To check for duplicate numbers in key
	maxVal := len(parts)

	for i, p := range parts {
		val, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid key part '%s': %v", p, err)
		}
		if val <= 0 || val > maxVal { // Key numbers should be 1 to N
			return nil, fmt.Errorf("key part '%d' out of range [1, %d]", val, maxVal)
		}
		if seen[val] { // Check if this number (1-based) has been seen
			return nil, fmt.Errorf("duplicate key part '%d'", val)
		}
		key[i] = val - 1 // Store as 0-indexed
		seen[val] = true
	}
	return key, nil
}

func rowTranspositionEncrypt(text string, keyStr string) (string, error) {
	text = prepareText(text, true)
	key, err := parseRowTranspositionKey(keyStr)
	if err != nil {
		return "", err
	}
	numCols := len(key)
	if numCols == 0 {
		return text, nil
	}
	numRows := (len(text) + numCols - 1) / numCols

	grid := make([][]rune, numRows)
	for i := range grid {
		grid[i] = make([]rune, numCols)
	}

	idx := 0
	for r := 0; r < numRows; r++ {
		for c := 0; c < numCols; c++ {
			if idx < len(text) {
				grid[r][c] = rune(text[idx])
				idx++
			} else {
				grid[r][c] = 'X'
			}
		}
	}

	var encryptedText strings.Builder
	// The 'key' array stores the 0-indexed column numbers in the order they should be read.
	// For example, if keyStr was "3-1-2", key would be {2, 0, 1}.
	// This means read column 2 (original 3rd col), then column 0 (original 1st col), then column 1 (original 2nd col).
	for _, colToRead := range key {
		for r := 0; r < numRows; r++ {
			encryptedText.WriteRune(grid[r][colToRead])
		}
	}
	return encryptedText.String(), nil
}

func rowTranspositionDecrypt(cipherText string, keyStr string) (string, error) {
	cipherText = prepareText(cipherText, true)
	key, err := parseRowTranspositionKey(keyStr) // key is {2,0,1} for "3-1-2"
	if err != nil {
		return "", err
	}
	numCols := len(key)
	if numCols == 0 {
		return cipherText, nil
	}
	textLen := len(cipherText)
	numRows := (textLen + numCols - 1) / numCols

	if textLen%numCols != 0 {
		// This indicates that the ciphertext length isn't a perfect multiple of the number of columns.
		// This can happen if the original text wasn't padded to a full rectangle before encryption,
		// or if the padding characters were stripped before this function was called.
		// For this implementation, we assume the ciphertext corresponds to a full grid.
		// A more robust solution might require knowing the original text length or handling partial last columns.
		log.Printf("Warning: Ciphertext length %d is not a multiple of key length %d. Decryption might be inexact if padding was irregular.", textLen, numCols)

	}

	grid := make([][]rune, numRows)
	for i := range grid {
		grid[i] = make([]rune, numCols)
	}

	idx := 0
	// Fill the grid column by column, in the order specified by the key.
	// 'key' tells us which original column comes first, second, etc. in the ciphertext.
	// So, key[0] is the first column in the ciphertext (e.g., original column 2).
	// key[1] is the second column in the ciphertext (e.g., original column 0).
	for _, originalColIndex := range key {
		for r := 0; r < numRows; r++ {
			if idx < textLen {
				grid[r][originalColIndex] = rune(cipherText[idx])
				idx++
			}
		}
	}

	var decryptedText strings.Builder
	for r := 0; r < numRows; r++ {
		for c := 0; c < numCols; c++ {
			// Ensure we don't read uninitialized runes if the grid was not perfectly filled
			// due to ciphertext length issues (though the current logic tries to fill it fully).
			if grid[r][c] != 0 { // Check for null rune, though padding 'X' is more likely
				decryptedText.WriteRune(grid[r][c])
			}
		}
	}
	// This basic version doesn't distinguish padding 'X' from actual 'X'.
	// For a more precise decryption, the original length or a non-text padding char would be needed.
	return decryptedText.String(), nil
}

// --- Playfair Cipher ---
func generatePlayfairMatrix(key string) [5][5]rune {
	key = prepareText(key, false)
	key = strings.ReplaceAll(key, "J", "I")

	var matrix [5][5]rune
	seen := make(map[rune]bool)
	idx := 0

	for _, r := range key {
		if !seen[r] {
			matrix[idx/5][idx%5] = r
			seen[r] = true
			idx++
		}
	}

	for _, r := range alphabet {
		if r == 'J' {
			continue
		}
		if !seen[r] {
			if idx < 25 {
				matrix[idx/5][idx%5] = r
				seen[r] = true
				idx++
			}
		}
	}
	return matrix
}

func findPlayfairPos(matrix [5][5]rune, char rune) (int, int) {
	if char == 'J' {
		char = 'I'
	}
	for r := 0; r < 5; r++ {
		for c := 0; c < 5; c++ {
			if matrix[r][c] == char {
				return r, c
			}
		}
	}
	return -1, -1
}

func preparePlayfairText(text string) string {
	text = prepareText(text, false)
	text = strings.ReplaceAll(text, "J", "I")

	var prepared strings.Builder
	i := 0
	runes := []rune(text) // Work with runes for correct indexing
	for i < len(runes) {
		char1 := runes[i]
		prepared.WriteRune(char1)
		if i+1 < len(runes) {
			char2 := runes[i+1]
			if char1 == char2 {
				prepared.WriteRune('X')
				// i remains the same, effectively processing char1 again with X in the next iteration of the outer loop
				// The loop increment is i+=2, so we need to adjust i to re-evaluate from the current char1.
				// No, this is wrong. We insert X, and then the pair is (char1, X). The next pair starts after X.
				// So, if text is "LL", it becomes "LX", then we process "LX".
				// The original loop structure was:
				// prepared.WriteRune(char1)
				// if i+1 < len(text)
				//   char2 = text[i+1]
				//   if char1 == char2: prepared.WriteRune('X'); i--; (this was problematic)
				//   else: prepared.WriteRune(char2)
				// else: prepared.WriteRune('X')
				// i+=2
				// Let's simplify:
				// Iterate through the text, forming digraphs.
			} else {
				prepared.WriteRune(char2)
				i++ // Move to the character after char2 for the next digraph
			}
		} else {
			prepared.WriteRune('X') // Append filler for odd length
		}
		i++ // Move to the start of the next digraph
	}

	// Revised logic for preparing Playfair text to handle digraphs correctly
	var newPrepared strings.Builder
	tempText := []rune(strings.ReplaceAll(prepareText(text, false), "J", "I"))
	k := 0
	for k < len(tempText) {
		newPrepared.WriteRune(tempText[k])
		if k+1 < len(tempText) {
			if tempText[k] == tempText[k+1] {
				newPrepared.WriteRune('X') // Insert filler
				// k remains, so next iteration starts with tempText[k] again, forming (tempText[k], 'X')
				// This is not quite right. We want to consume tempText[k] and 'X' as a pair.
				// Let's try a different approach for clarity.
			} else {
				newPrepared.WriteRune(tempText[k+1])
				k++ // Consumed two different characters
			}
		} else {
			newPrepared.WriteRune('X') // Odd length, add filler
		}
		k++ // Move to next character to start a new pair
	}

	// Final attempt at robust Playfair text preparation
	finalPrepared := strings.Builder{}
	cleanTextRunes := []rune(strings.ReplaceAll(prepareText(text, false), "J", "I"))
	idx := 0
	for idx < len(cleanTextRunes) {
		char1 := cleanTextRunes[idx]
		finalPrepared.WriteRune(char1)
		idx++
		if idx < len(cleanTextRunes) {
			char2 := cleanTextRunes[idx]
			if char1 == char2 {
				finalPrepared.WriteRune('X') // Insert X, char2 will be the start of the next pair
			} else {
				finalPrepared.WriteRune(char2)
				idx++
			}
		} else { // Last character, needs a filler
			finalPrepared.WriteRune('X')
		}
	}

	return finalPrepared.String()
}

func playfair(text string, key string, encrypt bool) string {
	matrix := generatePlayfairMatrix(key)

	// Playfair operates on letters only. Non-alpha chars are typically removed or handled separately.
	// This version will process only the alphabetic characters.
	// To preserve non-alpha characters, a more complex mapping before/after would be needed.
	alphaOnlyText := prepareText(text, false) // Get only A-Z
	if len(alphaOnlyText) == 0 {
		return text // If original text had no letters, return it as is.
	}

	processedText := preparePlayfairText(alphaOnlyText) // This now takes only alpha text
	if len(processedText)%2 != 0 {
		// This should not happen if preparePlayfairText is correct (always ensures even length)
		log.Println("Error: Playfair processed text has odd length: ", processedText)
		processedText += "X" // Failsafe, though should be investigated
	}

	var result strings.Builder
	shiftVal := 1
	if !encrypt {
		shiftVal = -1 // For decryption, we shift backwards
	}

	for i := 0; i < len(processedText); i += 2 {
		char1 := rune(processedText[i])
		char2 := rune(processedText[i+1])

		r1, c1 := findPlayfairPos(matrix, char1)
		r2, c2 := findPlayfairPos(matrix, char2)

		if r1 == -1 || c1 == -1 || r2 == -1 || c2 == -1 {
			result.WriteRune(char1)
			result.WriteRune(char2)
			log.Printf("Warning: Character not found in Playfair matrix: %c or %c. Matrix: %+v", char1, char2, matrix)
			continue
		}

		if r1 == r2 { // Same row
			result.WriteRune(matrix[r1][(c1+shiftVal+5)%5])
			result.WriteRune(matrix[r2][(c2+shiftVal+5)%5])
		} else if c1 == c2 { // Same column
			result.WriteRune(matrix[(r1+shiftVal+5)%5][c1])
			result.WriteRune(matrix[(r2+shiftVal+5)%5][c2])
		} else { // Rectangle
			result.WriteRune(matrix[r1][c2])
			result.WriteRune(matrix[r2][c1])
		}
	}

	finalResult := result.String()
	// Decryption might leave 'X's that were fillers.
	// A simple strategy: if an 'X' is between two identical letters, remove it.
	// Or if an 'X' is the last char and the original (alpha-only) text length was odd.
	// This is complex to do perfectly without more info.
	// For now, we return the result as is.
	// Example: "HELXLXO" decrypted from "HELXLOX" (if LLO was HELLO)
	// If decrypting and the result is "HELXLOWORLDX" and original was "HELLOWORLD"
	// We might try to remove X if it's between two identical letters upon decryption,
	// or if it's at the end and the length of the decrypted text (without it)
	// matches an expected pattern or if the original plaintext length was known.
	// This is a known complexity of Playfair.
	return finalResult
}

// --- Gin Handlers ---
func showIndexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func showCipherPage(c *gin.Context) {
	cipherType := c.Param("cipher")
	// Sanitize cipherType to prevent potential issues if it's used directly in file paths or complex logic
	// For now, it's used in titles and simple string comparisons, so it's relatively safe.
	pageTitle := strings.Title(strings.ReplaceAll(cipherType, "_", " ")) + " Cipher"

	keyHint := "Enter key"
	needsIntKey := false
	switch cipherType {
	case "caesar":
		keyHint = "Enter shift value (integer)"
		needsIntKey = true
	case "vigenere":
		keyHint = "Enter keyword (letters only)"
	case "monoalphabetic":
		keyHint = "Enter keyword to generate alphabet (letters only)"
	case "playfair":
		keyHint = "Enter keyword (letters only, J treated as I)"
	case "railfence":
		keyHint = "Enter number of rails (integer, >1)"
		needsIntKey = true
	case "row_transposition":
		keyHint = "Enter column order (e.g., 3-1-4-2 for 4 columns)"
	}

	c.HTML(http.StatusOK, "cipher_form.html", gin.H{
		"Title":       pageTitle,
		"CipherType":  cipherType,
		"KeyHint":     keyHint,
		"NeedsIntKey": needsIntKey,
	})
}

func processCipher(c *gin.Context) {
	cipherType := c.Param("cipher")
	var req CipherRequest
	if err := c.ShouldBind(&req); err != nil {
		c.HTML(http.StatusBadRequest, "result.html", gin.H{
			"Error":      "Invalid request: " + err.Error(),
			"CipherName": strings.Title(strings.ReplaceAll(cipherType, "_", " ")), // Provide CipherName for the back button
		})
		return
	}

	// For ciphers that operate only on letters, we might prepare text here.
	// However, some (like railfence) might want to preserve spaces/punctuation.
	// Individual cipher functions will handle their specific text preparation needs.
	// inputText := prepareText(req.Text, true) // Example: keep non-alpha initially

	var outputText string
	var err error
	encrypt := req.Operation == "encrypt"

	// Use req.Text directly; individual ciphers will prepare it as needed.
	// This ensures that ciphers like Railfence can operate on the original text if they choose to.
	rawInputText := req.Text

	switch cipherType {
	case "caesar":
		shift := req.KeyInt
		// Caesar preserves non-alpha, so pass rawInputText
		outputText = caesar(rawInputText, shift, encrypt)
	case "vigenere":
		key := req.Key // Vigenere's prepareText will clean the key
		// Vigenere preserves non-alpha in text, so pass rawInputText
		outputText = vigenere(rawInputText, key, encrypt)
	case "monoalphabetic":
		key := req.Key // Monoalphabetic's prepareText will clean the key
		// Monoalphabetic preserves non-alpha in text, so pass rawInputText
		outputText = monoalphabetic(rawInputText, key, encrypt)
	case "playfair":
		key := req.Key // Playfair's prepareText will clean the key
		// Playfair itself handles text prep (strips non-alpha, J->I, digraphs)
		outputText = playfair(rawInputText, key, encrypt)
	case "railfence":
		rails := req.KeyInt
		if rails <= 1 { // Rails must be greater than 1 for the cipher to make sense
			err = fmt.Errorf("number of rails must be greater than 1")
		} else {
			// Railfence can operate on text with spaces/symbols
			if encrypt {
				outputText = railfenceEncrypt(rawInputText, rails)
			} else {
				outputText = railfenceDecrypt(rawInputText, rails)
			}
		}
	case "row_transposition":
		// Row Transposition can also operate on text with spaces/symbols
		if encrypt {
			outputText, err = rowTranspositionEncrypt(rawInputText, req.Key)
		} else {
			outputText, err = rowTranspositionDecrypt(rawInputText, req.Key)
		}
	default:
		err = fmt.Errorf("unknown cipher type: %s", cipherType)
	}

	if err != nil {
		c.HTML(http.StatusInternalServerError, "result.html", gin.H{
			"Error":      err.Error(),
			"CipherName": strings.Title(strings.ReplaceAll(cipherType, "_", " ")), // For back button
			"InputText":  req.Text,                                                // Show original input even on error
			"Operation":  req.Operation,
		})
		return
	}

	c.HTML(http.StatusOK, "result.html", gin.H{
		"InputText":  req.Text, // Show the original user input
		"Key":        req.Key,
		"KeyInt":     req.KeyInt,
		"Operation":  req.Operation,
		"OutputText": outputText,
		"CipherName": strings.Title(strings.ReplaceAll(cipherType, "_", " ")),
	})
}

func showMultiLayerPage(c *gin.Context) {
	c.HTML(http.StatusOK, "multilayer_form.html", gin.H{
		"Title":     "Multilayer Cryptography",
		"MaxLayers": 5,
	})
}

func processMultiLayer(c *gin.Context) {
	var req MultiLayerRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("Multilayer Binding error: %v", err)
		c.Request.ParseForm() // Ensure form is parsed if not already
		log.Printf("Multilayer Form data: %v", c.Request.Form)
		c.HTML(http.StatusBadRequest, "result.html", gin.H{
			"Error":      "Invalid multilayer request: " + err.Error(),
			"CipherName": "Multilayer Operation",
		})
		return
	}

	currentText := req.Text
	var err error
	encrypt := req.Operation == "encrypt"

	log.Printf("Multilayer request received: %+v", req)
	log.Printf("Number of ciphers provided: %d", len(req.Ciphers))
	log.Printf("Number of keys provided: %d", len(req.Keys))
	log.Printf("Number of key_ints provided: %d", len(req.KeyInts))
	log.Printf("CipherCount field: %d", req.CipherCount)

	numLayersToProcess := req.CipherCount
	if numLayersToProcess == 0 && len(req.Ciphers) > 0 { // Fallback if cipher_count wasn't set right by JS
		numLayersToProcess = len(req.Ciphers)
	}
	if numLayersToProcess > len(req.Ciphers) { // Cap by actual data received
		numLayersToProcess = len(req.Ciphers)
	}

	// Create slices for processing based on numLayersToProcess
	// This is important if the form sends empty trailing elements due to fixed array sizing in HTML
	// or if cipher_count is the true determinant of active layers.
	activeCiphers := req.Ciphers[:numLayersToProcess]
	activeKeys := req.Keys[:numLayersToProcess]
	activeKeyInts := []string{}
	if len(req.KeyInts) >= numLayersToProcess {
		activeKeyInts = req.KeyInts[:numLayersToProcess]
	} else if len(req.KeyInts) > 0 { // If KeyInts is shorter, pad with "0" or handle error
		activeKeyInts = req.KeyInts
		for len(activeKeyInts) < numLayersToProcess {
			activeKeyInts = append(activeKeyInts, "0") // Default to "0" if not enough int keys
		}
	} else { // No key_ints at all, fill with "0"
		for len(activeKeyInts) < numLayersToProcess {
			activeKeyInts = append(activeKeyInts, "0")
		}
	}

	if !encrypt {
		// Reverse the order of operations for decryption
		for i, j := 0, numLayersToProcess-1; i < j; i, j = i+1, j-1 {
			activeCiphers[i], activeCiphers[j] = activeCiphers[j], activeCiphers[i]
			activeKeys[i], activeKeys[j] = activeKeys[j], activeKeys[i]
			activeKeyInts[i], activeKeyInts[j] = activeKeyInts[j], activeKeyInts[i]
		}
	}

	processingSteps := []string{}

	for i := 0; i < numLayersToProcess; i++ {
		cipherType := activeCiphers[i]
		if cipherType == "" {
			log.Printf("Skipping empty cipher selection at layer %d", i+1)
			continue
		}
		key := activeKeys[i]
		keyIntStr := activeKeyInts[i]

		var tempOutput string
		operationStr := "Encrypt"
		if !encrypt {
			operationStr = "Decrypt"
		}

		stepDescription := fmt.Sprintf("Step %d (%s): %s", i+1, operationStr, strings.Title(cipherType))
		if keyIntStr != "0" && (cipherType == "caesar" || cipherType == "railfence") {
			stepDescription += fmt.Sprintf(" with numeric key '%s'", keyIntStr)
		} else if key != "N/A" && key != "" {
			stepDescription += fmt.Sprintf(" with key '%s'", key)
		}

		switch cipherType {
		case "caesar":
			shift, convErr := strconv.Atoi(keyIntStr)
			if convErr != nil {
				err = fmt.Errorf("invalid numeric key '%s' for Caesar at layer %d: %v", keyIntStr, i+1, convErr)
				break
			}
			tempOutput = caesar(currentText, shift, encrypt)
		case "vigenere":
			tempOutput = vigenere(currentText, key, encrypt)
		case "monoalphabetic":
			tempOutput = monoalphabetic(currentText, key, encrypt)
		case "playfair":
			tempOutput = playfair(currentText, key, encrypt)
		case "railfence":
			rails, convErr := strconv.Atoi(keyIntStr)
			if convErr != nil {
				err = fmt.Errorf("invalid numeric key '%s' for Railfence at layer %d: %v", keyIntStr, i+1, convErr)
				break
			}
			if rails <= 1 {
				err = fmt.Errorf("invalid rails value %d for layer %d, must be > 1", rails, i+1)
				break
			}
			if encrypt {
				tempOutput = railfenceEncrypt(currentText, rails)
			} else {
				tempOutput = railfenceDecrypt(currentText, rails)
			}
		case "row_transposition":
			if encrypt {
				tempOutput, err = rowTranspositionEncrypt(currentText, key)
			} else {
				tempOutput, err = rowTranspositionDecrypt(currentText, key)
			}
		default:
			err = fmt.Errorf("unknown cipher '%s' in layer %d", cipherType, i+1)
		}

		if err != nil {
			log.Printf("Error during multilayer processing at layer %d (%s): %v", i+1, cipherType, err)
			break
		}
		currentText = tempOutput
		processingSteps = append(processingSteps, fmt.Sprintf("%s. Result: %s", stepDescription, currentText))
	}

	if err != nil {
		c.HTML(http.StatusInternalServerError, "result.html", gin.H{
			"Error":        err.Error(),
			"CipherName":   "Multilayer Operation",
			"InputText":    req.Text,
			"Operation":    req.Operation,
			"IsMultiLayer": true,
			"Steps":        processingSteps, // Show steps up to the point of error
		})
		return
	}

	c.HTML(http.StatusOK, "result.html", gin.H{
		"InputText":    req.Text,
		"Operation":    req.Operation,
		"OutputText":   currentText,
		"CipherName":   "Multilayer Operation",
		"Steps":        processingSteps,
		"IsMultiLayer": true,
	})
}

// --- Main Function ---
func main() {
	router := gin.Default()

	// Define custom template functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"replace": func(input, from, to string) string { // Renamed to avoid conflict if Gin adds its own "replace"
			return strings.ReplaceAll(input, from, to)
		},
		// Add other functions if needed
	}
	// Set the FuncMap for the templates
	router.SetFuncMap(funcMap)

	// Load HTML templates
	// Gin's LoadHTMLGlob internally uses html/template.ParseGlob.
	// If SetFuncMap is called before LoadHTMLGlob, the functions will be available.
	router.LoadHTMLGlob("templates/*")

	// Serve static files (if any, e.g. CSS)
	// router.Static("/static", "./static")

	// Routes
	router.GET("/", showIndexPage)
	router.GET("/cipher/:cipher", showCipherPage)
	router.POST("/cipher/:cipher", processCipher)

	router.GET("/multilayer", showMultiLayerPage)
	router.POST("/multilayer", processMultiLayer)

	fmt.Println("Server started at http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to run server: ", err)
	}
}
