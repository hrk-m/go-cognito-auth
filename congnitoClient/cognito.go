package congnitoClient

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/google/uuid"
)

type User struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserConfirmation struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

type UserLogin struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserLogOut struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserForgotPassword struct {
	Email string `json:"email" binding:"required,email"`
}

type UserPasswordReset struct {
	Email       string `json:"email" binding:"required,email"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type CognitoInterface interface {
	SignUp(user *User) error
	SignOut(token string) error
	ConfirmAccount(user *UserConfirmation) error
	SignIn(user *UserLogin) (string, error)
	GetUserByToken(token string) (*cognito.GetUserOutput, error)
	UpdatePassword(user *UserLogin) error
	ForgotPassword(user *UserForgotPassword) error
	ResetPassword(user *UserPasswordReset) error
}

type cognitoClient struct {
	cognitoClient *cognito.CognitoIdentityProvider
	appClientID   string
}

func NewCognitoClient(appClientId string) CognitoInterface {
	config := &aws.Config{Region: aws.String("ap-northeast-1")}
	sess, err := session.NewSession(config)
	if err != nil {
		panic(err)
	}
	client := cognito.New(sess)

	return &cognitoClient{
		cognitoClient: client,
		appClientID:   appClientId,
	}
}

func (c *cognitoClient) SignUp(user *User) error {
	userCognito := &cognito.SignUpInput{
		ClientId: aws.String(c.appClientID),
		Username: aws.String(user.Email),
		Password: aws.String(user.Password),
		UserAttributes: []*cognito.AttributeType{
			{
				Name:  aws.String("name"),
				Value: aws.String(user.Name),
			},
			{
				Name:  aws.String("email"),
				Value: aws.String(user.Email),
			},
			{
				Name:  aws.String("custom:custom_id"),
				Value: aws.String(uuid.NewString()),
			},
		},
	}
	_, err := c.cognitoClient.SignUp(userCognito)
	if err != nil {
		return err
	}
	return nil
}

func (c *cognitoClient) SignOut(token string) error {
	input := &cognito.GlobalSignOutInput{
		AccessToken: aws.String(token),
	}
	_, err := c.cognitoClient.GlobalSignOut(input)
	if err != nil {
		return err
	}
	return nil
}

func (c *cognitoClient) ConfirmAccount(user *UserConfirmation) error {
	confirmationInput := &cognito.ConfirmSignUpInput{
		Username:         aws.String(user.Email),
		ConfirmationCode: aws.String(user.Code),
		ClientId:         aws.String(c.appClientID),
	}
	_, err := c.cognitoClient.ConfirmSignUp(confirmationInput)
	if err != nil {
		return err
	}
	return nil
}

func (c *cognitoClient) SignIn(user *UserLogin) (string, error) {
	authInput := &cognito.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: aws.StringMap(map[string]string{
			"USERNAME": user.Email,
			"PASSWORD": user.Password,
		}),
		ClientId: aws.String(c.appClientID),
	}
	result, err := c.cognitoClient.InitiateAuth(authInput)
	if err != nil {
		return "", err
	}
	return *result.AuthenticationResult.AccessToken, nil
}

func (c *cognitoClient) GetUserByToken(token string) (*cognito.GetUserOutput, error) {
	input := &cognito.GetUserInput{
		AccessToken: aws.String(token),
	}
	result, err := c.cognitoClient.GetUser(input)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *cognitoClient) UpdatePassword(user *UserLogin) error {
	input := &cognito.AdminSetUserPasswordInput{
		UserPoolId: aws.String(os.Getenv("COGNITO_USER_POOL_ID")),
		Username:   aws.String(user.Email),
		Password:   aws.String(user.Password),
		Permanent:  aws.Bool(true),
	}
	_, err := c.cognitoClient.AdminSetUserPassword(input)
	if err != nil {
		return err
	}
	return nil
}

func (c *cognitoClient) ForgotPassword(user *UserForgotPassword) error {
	input := &cognito.ForgotPasswordInput{
		ClientId: aws.String(c.appClientID),
		Username: aws.String(user.Email),
	}
	_, err := c.cognitoClient.ForgotPassword(input)
	if err != nil {
		return err
	}
	return nil
}

func (c *cognitoClient) ResetPassword(user *UserPasswordReset) error {
	// 確認コードを使って新しいパスワードを設定
	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         aws.String(c.appClientID),
		Username:         aws.String(user.Email),
		ConfirmationCode: aws.String(user.Code),
		Password:         aws.String(user.NewPassword),
	}
	_, err := c.cognitoClient.ConfirmForgotPassword(input)
	if err != nil {
		fmt.Println("err", err)
		return err
	}
	return nil
}
