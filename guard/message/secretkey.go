package message

import "math/rand"
import "time"
import "fmt"

/* key : the first adn the second byte are zeor
   the rest are random
*/
type SecretKey struct {
	Elem [6]byte
}

func (key *SecretKey) IsValid() bool {
	return key.Elem[0] == 0
}

func Contruct(data []byte) *SecretKey {
	key := new(SecretKey)
	for i, _ := range key.Elem {
		key.Elem[i] = data[i]
	}
	return key
}

/* Generate a random secret key */
func Generator() *SecretKey {
	key := new(SecretKey)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i, _ := range key.Elem {
		if i == 0 {
			key.Elem[i] = 0
		} else {
			key.Elem[i] = byte(r.Intn(256))
		}
	}

	return key
}

func Compare(key1 *SecretKey, key2 *SecretKey) bool {
	return key1.Elem == key2.Elem
}

func ConvToString(key *SecretKey) string {
	var str string
	for i, v := range key.Elem {
		if i < len(key.Elem)-1 {
			str += fmt.Sprintf("%02X", v) + ":"
		} else {
			str += fmt.Sprintf("%02X", v)
		}
	}
	return str
}

/*
* function defination:
*            | 48 + x % 10, x(-[0, 59], x(-N      char: 0-9
* y = f(x) = | 65 + x % 26, x(-[60, 157], x(-N    char: a-z
*            | 97 + x % 26, x(-[158, 255], x(-N   char: A-Z
 */

func AlnumGenerator(key *SecretKey) string {
	prefix := "nf-"

	var alnum [5]byte
	for i, v := range key.Elem {
		if i == 0 {
			continue
		}

		alnum[i-1] = func(c byte) byte {
			var r byte = 0
			if c <= 59 {
				r = 48 + c%10
			} else if c <= 157 {
				r = 65 + c%26
			} else {
				r = 97 + c%26
			}
			return r
		}(v)
	}
	return prefix + string(alnum[:])
}
