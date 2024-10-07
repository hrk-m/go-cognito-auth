# 概要

このプロジェクトは、AWS Cognito を使用してユーザー認証を行う Go 言語の Web アプリケーションです。
Gin フレームワークを使用して API エンドポイントを提供し、ユーザーの登録、ログイン、ログアウト、パスワードのリセットなどの機能を実装しています。

## 環境変数

機密情報などは環境変数を利用しています。

[direnv](https://github.com/direnv/direnv)を利用する場合は `/.env.sample` を参考に `/.env` で指定してください。

## プロジェクトの立ち上げ

```
go run cmd/main.go
```

## API

`./go-cognito-auth.postman_collection.json` をpostmanに取り込んで確認ください.
