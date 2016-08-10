package secret

/* key : the first adn the second byte are zeor
   the rest are random
*/
type SecretKey struct {
	Key [6]byte
}

/* Generate a random secret key */
func KeyGenerator() *SecretKey {
	return nil
}

func KeyCompare(key1 *SecretKey, Key2 *SecretKey) bool {
	return false
}
