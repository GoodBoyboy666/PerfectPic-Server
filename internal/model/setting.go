package model

type Setting struct {
	Key      string `gorm:"primaryKey"`
	Value    string
	Desc     string
	Category string
}
