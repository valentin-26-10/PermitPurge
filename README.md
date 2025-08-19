# PermitPurge

> Найди и обезвредь **бесконечные разрешения** (ERC-20 `approve` и Uniswap **Permit2**) в своём кошельке.

## Зачем это нужно

- Почти каждый DEX/маркетплейс просит `approve` на **бесконечную сумму**. Это удобно, но рискованно.
- **Permit2** (Uniswap) удобен для батч-сигнатур, но скрывает «виртуальные» allowances, о которых многие не догадываются.
- **PermitPurge** сканирует кошелёк, находит активные и «бесконечные» approvals к популярным контрактам, оценивает риск и готовит **план ревокации**.

## Возможности

- Поиск токенов, где кошелёк выдавал `Approval` (через лог-сканирование за окно блоков).
- Проверка текущих `allowance(owner, spender)` по ERC-20.
- Проверка `Permit2.allowance(user, token, spender)` (возвращает amount, expiration).
- Оценка риска (LOW/MEDIUM/HIGH/CRITICAL).
- Экспорт: таблица (консоль/CSV) + `revoke_plan.json` с сырыми calldata:
  - `approve(spender, 0)` для ERC-20;
  - `approve(token, spender, 0, 0)` **или** `lockdown([token], spender)` для Permit2.

## Установка

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
