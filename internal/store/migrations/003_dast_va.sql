-- DAST / VA finding 欄位
--
-- 新增 url host port method 四欄 支援 Nuclei DAST 與 Nmap VA 引擎
-- 既有 SAST/SCA/Secret finding 此四欄為 NULL 向後相容

ALTER TABLE findings ADD COLUMN url    TEXT;
ALTER TABLE findings ADD COLUMN host   TEXT;
ALTER TABLE findings ADD COLUMN port   TEXT;
ALTER TABLE findings ADD COLUMN method TEXT;
