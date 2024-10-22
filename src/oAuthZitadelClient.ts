/* eslint-disable no-console */
import type {
  AxiosInstance,
  InternalAxiosRequestConfig,
} from 'axios'
import pkceChallenge from 'pkce-challenge'

export interface OAuth2VueClientOptions {
  authorization: {
    clientId: string
    grantType: GrantType
    logoutUrl: string
    postLogoutRedirectUri: string
    redirectUri: string
    scopes: string[]
    url: string
  }
  axios: AxiosInstance
  /*
   * If offline is true, the client wil bypass everything and work without a real login
   */
  offline?: boolean
  tokenEndpoint: string
  userInfoEndpoint?: string
}

interface ZitadelClientOptions {
  client_id: string
  code?: string
  code_verifier?: string
  grant_type: GrantType
  id_token?: string
  redirect_uri?: string
  scopes?: string
  state?: string
}

export interface OAuth2Tokens {
  expires_at: number
  access_token: string
  id_token: string
  refresh_token: string
  scope: string
  token_type: string
}

export type GrantType = 'ad' | 'authorization_code' | 'password' | 'refresh_token'

interface TokenStoreOptions {
  clientId: string
  axios: AxiosInstance
  scopes?: string[]
  tokenEndpoint: string
}

const LOCAL_STORAGE_KEY = 'tokens'

interface Token {
  exp: number
}

function decodeToken(token: string): Token {
  const base64Url = token.split('.')[1]
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split('')
      .map((c) => `%${(`00${c.charCodeAt(0).toString(16)}`).slice(-2)}`)
      .join(''),
  )

  return JSON.parse(jsonPayload)
}

class TokenStore {
  private _promise: Promise<void> | null = null

  constructor(
    private readonly options: TokenStoreOptions,
    tokens?: OAuth2Tokens,
  ) {
    this.setTokens(tokens)
  }

  private accessTokenExpired(): boolean {
    return Date.now() >= this.getTokens().expires_at
  }

  private async getNewAccessToken(refreshToken: string): Promise<OAuth2Tokens> {
    const response = await this.options.axios.post<OAuth2Tokens>(
      this.options.tokenEndpoint,
      {
        client_id: this.options.clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: this.options.scopes?.join(' '),
      },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    )

    const decodedToken = decodeToken(response.data.access_token)

    return {
      expires_at: decodedToken.exp * 1000,
      access_token: response.data.access_token,
      id_token: response.data.id_token,
      refresh_token: response.data.refresh_token,
      scope: response.data.scope,
      token_type: response.data.token_type,
    }
  }

  private async refreshToken(): Promise<void> {
    if (this._promise != null) {
      return this._promise
    }

    this._promise = new Promise((resolve, reject) => {
      this.getNewAccessToken(this.getRefreshToken())
        .then((tokens) => {
          this.setTokens(tokens)
          resolve()
        })
        .catch(() => {
          console.log('Failed to refresh access token, trying again...')

          setTimeout(() => {
            this.getNewAccessToken(this.getRefreshToken())
              .then((tokens) => {
                this.setTokens(tokens)
                resolve()
              })
              .catch(() => {
                reject(new Error('Failed to refresh access token'))
              })
          }, 1000)
        })
        .finally(() => {
          this._promise = null
        })
    })

    return await this._promise
  }

  public clearTokens(): void {
    localStorage.removeItem(LOCAL_STORAGE_KEY)
  }

  public async getAccessToken(): Promise<string> {
    if (this.accessTokenExpired()) {
      await this.refreshToken()
    }

    return this.getTokens().access_token
  }

  public getRefreshToken(): string {
    return this.getTokens().refresh_token
  }

  public getTokens(): OAuth2Tokens {
    return JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY) as string) as OAuth2Tokens
  }

  public setTokens(tokens?: OAuth2Tokens): void {
    if (tokens === undefined) {
      return
    }

    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(tokens))
  }
}

export class OAuth2ZitadelClient {
  private client: TokenStore | null = null
  private readonly offline: boolean

  constructor(private readonly options: OAuth2VueClientOptions) {
    this.offline = options.offline ?? false
    this.client = this.createClient()
  }

  private createClient(tokens?: OAuth2Tokens): TokenStore {
    return new TokenStore(
      {
        clientId: this.options.authorization.clientId,
        axios: this.options.axios,
        tokenEndpoint: this.options.tokenEndpoint,
      },
      tokens,
    )
  }

  private async login(clientOptions: ZitadelClientOptions): Promise<TokenStore> {
    const response = await this.options.axios.post<OAuth2Tokens>(this.options.tokenEndpoint, clientOptions, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })

    const decodedToken = decodeToken(response.data.access_token)

    return new TokenStore(
      {
        clientId: clientOptions.client_id,
        axios: this.options.axios,
        scopes: this.options.authorization.scopes,
        tokenEndpoint: this.options.tokenEndpoint,
      },
      {
        expires_at: decodedToken.exp * 1000,
        access_token: response.data.access_token,
        id_token: response.data.id_token,
        refresh_token: response.data.refresh_token,
        scope: response.data.scope,
        token_type: response.data.token_type,
      },
    )
  }

  private removeClient(): void {
    this.client?.clearTokens()
    this.client = null
  }

  async addAuthorizationHeader(
    config: InternalAxiosRequestConfig<unknown>,
  ): Promise<InternalAxiosRequestConfig<unknown>> {
    const client = this.getClient()

    if (client === null) {
      return config
    }

    if (this.offline) {
      return config
    }

    try {
      const token = await client.getAccessToken()

      config.headers.Authorization = `Bearer ${token}`
    }
    catch (error) {
      console.log('Failed to get access token, logging out', error)
      this.client?.clearTokens()

      throw new Error('Failed to get access token')
    }

    return config
  }

  public getClient(): TokenStore | null {
    return this.client
  }

  public async getLoginUrl(): Promise<string> {
    const searchParams = new URLSearchParams()

    const codes = await pkceChallenge()

    localStorage.setItem('code_verifier', codes.code_verifier)

    searchParams.append('client_id', this.options.authorization.clientId)
    searchParams.append('redirect_uri', this.options.authorization.redirectUri)
    searchParams.append('response_type', 'code')
    searchParams.append('prompt', 'login')
    searchParams.append('scope', this.options.authorization.scopes?.join(' ') ?? '')
    searchParams.append('code_challenge', codes.code_challenge)
    searchParams.append('code_challenge_method', 'S256')

    return `${this.options.authorization.url}?${searchParams.toString()}`
  }

  public getLogoutUrl(): string {
    const searchParams = new URLSearchParams()

    searchParams.append('client_id', this.options.authorization.clientId)
    searchParams.append('post_logout_redirect_uri', this.options.authorization.postLogoutRedirectUri)

    return `${this.options.authorization.logoutUrl}?${searchParams.toString()}`
  }

  async getUserInfo<TData>(): Promise<TData> {
    if (this.client === null) {
      throw new Error('Client is not logged in')
    }

    if (this.options.userInfoEndpoint === undefined) {
      throw new Error('User info endpoint is not defined')
    }

    const response = await this.options.axios.get(this.options.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${this.client.getTokens().access_token}`,
      },
    })

    return response.data
  }

  public isLoggedIn(): boolean {
    if (this.options.offline === true) {
      return true
    }

    const client = this.getClient()

    return client?.getTokens() != null
  }

  public async loginAuthorization(code: string): Promise<void> {
    if (this.options.offline === true) {
      this.loginOffline()

      return
    }

    const codeVerifier = localStorage.getItem('code_verifier')

    const tokenStore = await this.login({
      client_id: this.options.authorization.clientId,
      code,
      code_verifier: codeVerifier ?? undefined,
      grant_type: this.options.authorization.grantType,
      redirect_uri: this.options.authorization.redirectUri,
      scopes: this.options.authorization.scopes?.join(' ') ?? '',
    })

    const tokens = tokenStore.getTokens()

    localStorage.setItem('id_token', tokens.id_token)

    this.client = this.createClient(tokens)

    localStorage.removeItem('code_verifier')
  }

  public loginOffline(): void {
    this.client?.setTokens({
      expires_at: 0,
      access_token: '',
      id_token: '',
      refresh_token: '',
      scope: '',
      token_type: '',
    })
  }

  public logout(): void {
    this.removeClient()
  }
}
