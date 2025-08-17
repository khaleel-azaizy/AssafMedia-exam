## Implemented Features

-  **Secure OTP login (username-only)**  
  Users enter just a username. A 6-digit OTP is generated and (optionally) emailed. Rate limits + cooldown prevent abuse.  
  *Server:* `auth_api.php` (`request_otp`, `verify_otp`)  
  *Client:* `login/index.html` (vanilla or React version)

-  **Token-based auth on all API routes**  
  After OTP verification, the server issues a token. All requests include  
  `Authorization: Bearer <token>` and are validated on the server.  
  *Server:* `api.php` (global `require_auth_or_die()`), `auth_api.php` (token issue/revoke)  
  *Client:* `main.js` → `postToServer()` auto-adds header

-  **Correct user header (name & avatar) + proper logout**  
  Header shows the *logged-in* user’s avatar and name. Logout clears token locally and revokes it server-side (`logout` / `logout_all`).  
  *Server:* `auth_api.php` (revoke), `api.php` (auth required)  
  *Client:* `main.js` (UI + localStorage cleanup)

-  **Paper-clip image attach + desktop drag & drop**  
  Clicking the paper clip opens a small popup to select an image; on desktop you can drag an image into the drop zone. Validates type/size, uploads, and closes the popup on success.  
  *Client:* `main.js` (popup + drag&drop), `index.css` (popup styling)

-  **Image mirroring to recipient thread**  
  When you send an image, two rows are written: sender’s view (`is_from_me=1`) and recipient’s view (`is_from_me=0`) so both sides see it.  
  *Server:* `api.php?data=send_wa_img_msg`

-  **Incoming-message sound notification**  
  Plays a short sound for new messages; toggleable and with a configurable sound URL.  
  *Client:* `main.js` (`playIncommingMsgSound`)

-  **Lazy loading for messages**  
  Messages load in pages and fetch more on demand / interval. Keeps the UI snappy and reduces payloads.  
  *Client:* `main.js` (`getChats`, `loadMsgsFromServerByContactId`, `loadNewMsgs`)

-  **Stability fixes & cleanup**  
  Fixed `$GLOBALS` misuse, hardened MySQL connection + timezones, sanitized `LIMIT`, consistent error logging, and cleaned up token/header parsing across environments (Apache/IIS/CGI).
