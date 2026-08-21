# VoiceInbox — 画面

音声メモを読むための、静的な Web ページです。
GitHub Pages から配信されます。ビルドもフレームワークも使いません。

```
index.html   一覧・ゴミ箱・設定
setup.html   はじめかた（鍵の作り方）
app.js       画面のロジック
style.css    配色と書体
```

## このリポジトリの決まり

- **メモの中身は 1 バイトもここに置きません。** 保存先は別の private リポジトリの Issue です。
- **接続先はコードに書きません。** オーナー名・リポジトリ名は、利用者が画面で入力します。
- **トークンはコードにも履歴にも書きません。** 各端末のブラウザの中だけに保存されます。
- Issues 機能は無効にしてあります（書き込む経路を塞ぐため）。

`.gitignore` と `.githooks/pre-commit` で、実データの誤コミットを機械的に止めています。
clone したら一度だけ次を実行してください。

```sh
git config core.hooksPath .githooks
```

## 動かし方

そのままブラウザで `index.html` を開いても動きます。
配信は GitHub Pages（Settings → Pages → Source: main / root）です。
