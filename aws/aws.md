## CloudFormationテンプレート利用時の注意

- `aws/infra.yaml` はgit管理可能な状態ですが、以下の点に注意してください。
    - `AcmCertificateArn` のDefault値は空になっています。デプロイ時に有効なACM証明書のARNを指定してください。
    - Cognitoの `CallbackURLs` および `LogoutURLs` はコメントアウトされています。ご自身のALB DNS名等、環境に合わせて適宜修正してください。
    - その他、機密情報や環境依存値は直接記載しないようご注意ください。
