# oAuth Vue Client

This is a Vue.js client that uses our customer oAuthClient package to authenticate users with our oAuth server.

### Installation

```bash
pnpm install @wisemen/oauth-vue-client
```

### Usage

```typescript
// src/libs/oAuth.lib.ts
import { OAuth2VueClient } from '@appwise/oauth2-vue-client'
import axios from 'axios'

const API_CLIENT_ID = import.meta.env.API_CLIENT_ID
const API_CLIENT_SECRET = import.meta.env.API_CLIENT_SECRET
const API_AUTH_URL = import.meta.env.API_AUTH_URL

export const oAuthClient = new OAuth2VueClient({
  axios,
  clientId: API_CLIENT_ID,
  clientSecret: API_CLIENT_SECRET,
  tokenEndpoint: `${API_AUTH_URL}/token`,
})
```

```typescript
// src/libs/axios.lib.ts
axios.interceptors.request.use((config) => addAuthorizationHeader(oAuthClient, config))
```
