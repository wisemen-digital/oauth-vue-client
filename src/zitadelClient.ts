/* eslint-disable no-console */
import type {
  AxiosInstance,
  InternalAxiosRequestConfig,
} from 'axios'
import pkceChallenge from 'pkce-challenge'

import type { OAuth2Tokens } from './tokenStore'
import { TokenStore } from './tokenStore'

export interface OAuth2VueClientOptions {
  /*
  * The client ID
  */
  clientId: string
  /*
  * The organization ID
  */
  organizationId: string
  /*
  * The Axios instance to use for requests
  */
  axios: AxiosInstance
  /*
  * The base URL of the OAuth2 server
  */
  baseUrl: string
  /*
  * The URL to redirect to after login
  */
  loginRedirectUri: string
  /*
   * If offline is true, the client wil bypass everything and work without a real login
   */
  offline?: boolean
  /*
  * The URL to redirect to after logout
  */
  postLogoutRedirectUri: string
  /*
  * The scopes to request from the OAuth2 server
  * Default: ['openid', 'profile', 'email', 'offline_access', `urn:zitadel:iam:org:id:${organizationId}`]
  */
  scopes?: string[]
}

export class ZitadelClient {
  private client: TokenStore | null = null
  private readonly offline: boolean

  constructor(private readonly options: OAuth2VueClientOptions) {
    this.offline = options.offline ?? false
    this.client = this.createClient()
  }

  private createClient(tokens?: OAuth2Tokens): TokenStore {
    return new TokenStore(
      {
        clientId: this.options.clientId,
        axios: this.options.axios,
        redirectUri: this.options.loginRedirectUri,
        scopes: this.options.scopes ?? this.getDefaultScopes(),
        tokenEndpoint: `${this.options.baseUrl}/oauth/v2/token`,
      },
      tokens,
    )
  }

  private getDefaultScopes(): string[] {
    return [
      'openid',
      'profile',
      'email',
      'offline_access',
      `urn:zitadel:iam:org:id:${this.options.organizationId}`,
    ]
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

    const scopes = this.options.scopes ?? this.getDefaultScopes()

    localStorage.setItem('code_verifier', codes.code_verifier)

    searchParams.append('client_id', this.options.clientId)
    searchParams.append('redirect_uri', this.options.loginRedirectUri)
    searchParams.append('response_type', 'code')
    searchParams.append('prompt', 'login')
    searchParams.append('scope', scopes.join(' '))
    searchParams.append('code_challenge', codes.code_challenge)
    searchParams.append('code_challenge_method', 'S256')

    return `${this.options.baseUrl}/oauth/v2/authorize?${searchParams.toString()}`
  }

  public getLogoutUrl(): string {
    const searchParams = new URLSearchParams()

    searchParams.append('client_id', this.options.clientId)
    searchParams.append('post_logout_redirect_uri', this.options.postLogoutRedirectUri)

    return `${this.options.baseUrl}/oidc/v1/end_session?${searchParams.toString()}`
  }

  async getUserInfo<TData>(): Promise<TData> {
    if (this.client === null) {
      throw new Error('Client is not initialized')
    }

    const response = await this.options.axios.get(`${this.options.baseUrl}/oidc/v1/userinfo`, {
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

  public async login(code: string): Promise<void> {
    if (this.options.offline === true) {
      this.loginOffline()

      return
    }

    if (this.client === null) {
      throw new Error('Client is not initialized')
    }

    await this.client.login(code)
  }

  public loginOffline(): void {
    if (this.client === null) {
      throw new Error('Client is not initialized')
    }

    this.client.setMockTokens()
  }

  public logout(): void {
    this.client?.clearTokens()
    this.client = null
  }
}
