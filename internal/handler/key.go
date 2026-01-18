package handler

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sebastian-mora/aegis/internal/signer"
)

type Keyhandler interface {
	PublicKey(context.Context) (string, error)
}

type KMSKeyHandler struct {
	KmsKeyId  string
	kmsClient signer.AwsKMSApi
}

func NewKmsKeyHandler(kmsClient signer.AwsKMSApi, kmsKeyId string) *KMSKeyHandler {
	return &KMSKeyHandler{
		KmsKeyId:  kmsKeyId,
		kmsClient: kmsClient,
	}
}

func (k *KMSKeyHandler) PublicKey(ctx context.Context) (string, error) {

	res, err := k.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &k.KmsKeyId})
	if err != nil {
		return "", err
	}

	return string(res.PublicKey), nil
}
