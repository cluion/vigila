# 安全政策

## 支援版本

Vigila 尚在 `v0.x` 快速迭代階段，安全修補一律以最新的 `v0.x` 版發布。請盡量使用最新版。

| 版本 | 支援狀態 |
|------|---------|
| 最新 `v0.x` | ✅ 支援 |
| 較舊版本 | ❌ 請升級 |

## 回報漏洞

**請勿以公開 issue 回報安全漏洞。**

請透過 GitHub 的私密漏洞回報功能（repository 的 **Security → Report a vulnerability**）提交。回報時請盡量包含：

- 受影響的元件與版本
- 重現步驟或概念驗證
- 潛在影響評估

我們會盡快確認收到，並在修補後於 [CHANGELOG.md](./CHANGELOG.md) 揭露（可協調揭露時間）。

## 範圍說明

Vigila 本身是一套整合多引擎的安全掃描器。請留意：

- **掃描授權**：僅對你有權掃描的目標執行 DAST／VA 掃描（nikto／sqlmap／nuclei／zap／nmap／openvas）。對未授權目標掃描可能觸法。
- **引擎 binary**：Vigila 以 subprocess 呼叫外部引擎，不連結其程式碼；引擎自身的漏洞請回報至各引擎專案。
- **供應鏈**：managed install 對有簽章的引擎做 cosign keyless 驗證，未簽章者維持 checksum-only（見 README）。
