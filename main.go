package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hrk-m/go-cognito-auth/congnitoClient"
	"github.com/joho/godotenv"
)

type UserResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	CustomID      string `json:"custom_id"`
	EmailVerified bool   `json:"email_verified"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	cognitoClient := congnitoClient.NewCognitoClient(os.Getenv("COGNITO_CLIENT_ID"))
	r := gin.Default()

	r.POST("api/user", func(context *gin.Context) {
		err := CreateUser(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"message": "user created"})
	})

	r.POST("api/user/confirmation", func(context *gin.Context) {
		err := ConfirmAccount(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"message": "user confirmed"})
	})

	r.POST("api/user/login", func(context *gin.Context) {
		token, err := SignIn(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"token": token})
	})

	r.POST("api/user/logout", func(context *gin.Context) {
		isSignOut, err := SignOut(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{"success": isSignOut})
	})

	r.GET("api/user", func(context *gin.Context) {
		user, err := GetUserByToken(context, cognitoClient)
		if err != nil {
			if err.Error() == "token not found" {
				context.JSON(http.StatusUnauthorized, gin.H{"error": "token not found"})
				return
			}
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"user": user})
	})

	r.PATCH("api/user/password", func(context *gin.Context) {
		err := UpdatePassword(context, cognitoClient)
		if err != nil {
			if err.Error() == "token not found" {
				context.JSON(http.StatusUnauthorized, gin.H{"error": "token not found"})
				return
			}
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"message": "password updated"})
	})

	// パスワードリセットコード生成のエンドポイントを追加
	r.POST("api/user/password/forgot", func(context *gin.Context) {
		err := ForgotPassword(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"message": "password reset code sent"})
	})

	// パスワードリセットのエンドポイントを追加
	r.POST("api/user/password/reset", func(context *gin.Context) {
		err := ResetPassword(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"message": "password reset email sent"})
	})

	fmt.Println("Server is running on port 8080")
	err = r.Run(":8080")
	if err != nil {
		panic(err)
	}
}

func CreateUser(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.User
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}

	err := cognito.SignUp(&user)
	if err != nil {
		return errors.New("could not create use")
	}

	return nil
}

func ConfirmAccount(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.UserConfirmation
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}

	err := cognito.ConfirmAccount(&user)
	if err != nil {
		return errors.New("could not confirm user")
	}

	return nil
}

func SignIn(c *gin.Context, cognito congnitoClient.CognitoInterface) (string, error) {
	var user congnitoClient.UserLogin
	if err := c.ShouldBindJSON(&user); err != nil {
		return "", errors.New("invalid json")
	}

	token, err := cognito.SignIn(&user)
	if err != nil {
		return "", errors.New("could not sign in")
	}

	return token, nil
}

func SignOut(c *gin.Context, cognito congnitoClient.CognitoInterface) (bool, error) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return false, errors.New("token not found")
	}

	err := cognito.SignOut(token)
	if err != nil {
		return false, errors.New("could not logout")
	}

	return true, nil
}

func GetUserByToken(c *gin.Context, cognito congnitoClient.CognitoInterface) (*UserResponse, error) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return nil, errors.New("token not found")
	}

	cognitoUser, err := cognito.GetUserByToken(token)
	if err != nil {
		return nil, errors.New("could not get user")
	}

	user := &UserResponse{}
	for _, attribute := range cognitoUser.UserAttributes {
		switch *attribute.Name {
		case "sub":
			user.ID = *attribute.Value
		case "name":
			user.Name = *attribute.Value
		case "email":
			user.Email = *attribute.Value
		case "custom:custom_id":
			user.CustomID = *attribute.Value
		case "email_verified":
			emailVerified, err := strconv.ParseBool(*attribute.Value)
			if err == nil {
				user.EmailVerified = emailVerified
			}
		}
	}
	return user, nil
}

func UpdatePassword(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return errors.New("token not found")
	}

	var user congnitoClient.UserLogin
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}

	err := cognito.UpdatePassword(&user)
	if err != nil {
		return errors.New("could not update password")
	}

	return nil
}

func ForgotPassword(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.UserForgotPassword
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}

	err := cognito.ForgotPassword(&user)
	if err != nil {
		return errors.New("could not send password reset code")
	}

	return nil
}

// パスワードリセットの関数を追加.
func ResetPassword(c *gin.Context, cognito congnitoClient.CognitoInterface) error {
	var user congnitoClient.UserPasswordReset
	if err := c.ShouldBindJSON(&user); err != nil {
		return errors.New("invalid json")
	}

	err := cognito.ResetPassword(&user)
	if err != nil {
		return errors.New("could not reset password")
	}

	return nil
}
