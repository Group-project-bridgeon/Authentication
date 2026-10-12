package helper

import "golang.org/x/crypto/bcrypt"

type Bcrypt struct{cost int}

func NewBcrypt() *Bcrypt {return &Bcrypt{cost:12}}

func (b *Bcrypt) Hash(plain string) (string,error) {
	h, err:=bcrypt.GenerateFromPassword([]byte(plain),b.cost)
	return string(h),err
}

func (b *Bcrypt) Compare(hash,plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash),[]byte(plain))
}