# Security Specification — 나의 AI 프롬프트 창고 (Public Safe Rules)

## 1. Data Invariants
- **Strict Collection Boundary**: ONLY `/prompts/{promptId}` is accessible. Every other collection and path is blocked for both reading and writing by the global default-deny catch-all.
- **Public Read, Admin-Only Write (RBAC)**:
  - Anyone (including unauthenticated guests) can read (`get`, `list`) documents in `/prompts/{promptId}`.
  - Only the single verified administrator (`request.auth != null && request.auth.token.email == 'ansejun333@gmail.com' && request.auth.token.email_verified == true`) may `create`, `update`, or `delete` documents in `/prompts/{promptId}`.
- **Exact Field Shape**: Every `Prompt` document must contain exactly `['title', 'category', 'content', 'createdAt']`—no shadow fields permitted.
- **Content Capacity & Bounds**:
  - `title`: string, 1 to 100 characters.
  - `category`: string in `['사진 합성', '스타일 변환', '캐릭터·포스터']`.
  - `content`: string, 1 to 10,000 characters (supports long 1,000+ character prompts safely).
  - `createdAt`: server timestamp (`request.time`) on create; strictly immutable on update (`incoming().createdAt == existing().createdAt`).

## 2. Adversarial Payloads ("Dirty Dozen")
1. **Unauthenticated Create/Update/Delete**: Guest attempts to write to `/prompts/x` -> Rejected (`isAdmin()`).
2. **Non-Admin Authenticated User**: Signed-in user with `other@gmail.com` attempts write -> Rejected (`email == 'ansejun333@gmail.com'`).
3. **Email Spoofing Attack**: User with `email == 'ansejun333@gmail.com'` and `email_verified == false` -> Rejected (`email_verified == true`).
4. **Shadow Field Injection on Create**: Admin sends `isAdmin: true` extra field -> Rejected (`keys().hasOnly(...)`).
5. **Oversized Content Payload (>10,000 chars)**: Admin sends 12,000-char content -> Rejected (`content.size() <= 10000`).
6. **Oversized Title (>100 chars)**: Admin sends 150-char title -> Rejected (`title.size() <= 100`).
7. **Empty Title / Empty Content**: Admin sends empty string -> Rejected (`size() >= 1`).
8. **Invalid Category Value**: Admin sends `"기타"` -> Rejected (`isValidCategory`).
9. **Forged Backdated Timestamp on Create**: Client sends custom timestamp -> Rejected (`createdAt == request.time`).
10. **Mutating `createdAt` on Update**: Updating `createdAt` -> Rejected (`incoming().createdAt == existing().createdAt`).
11. **ID Poisoning**: Writing to `/prompts/bad$id!...` -> Rejected (`isValidId(promptId)`).
12. **Access to Any Other Collection**: Reading or writing `/users/123` or `/test/connection` -> Rejected (default deny catch-all).
