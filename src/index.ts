import type { OAuth2ClientGrantType, OAuth2ClientTokensWithExpiration } from '@appwise/oauth2-client'
import { OAuth2Client, TokenStore } from '@appwise/oauth2-client'
import type { Axios, AxiosInstance, InternalAxiosRequestConfig } from 'axios'

interface OAuth2VueClientOptions {
  axios: Axios | AxiosInstance
  clientId: string
  clientSecret: string
  tokenEndpoint: string
  scopes?: string[]
}

export class OAuth2VueClient {
  private oAuthFactory: OAuth2Client
  private client: TokenStore | null = null

  constructor(private readonly options: OAuth2VueClientOptions) {
    const {
      axios,
      clientId,
      clientSecret,
      tokenEndpoint,
    } = options

    this.oAuthFactory = new OAuth2Client({
      axios,
      clientId,
      clientSecret,
      tokenEndpoint,
    })

    const tokens = this.loadTokensFromLocalStorage()

    if (tokens !== null)
      this.client = this.createClient(tokens)
  }

  private createClient(tokens: OAuth2ClientTokensWithExpiration): TokenStore {
    const {
      axios,
      clientId,
      clientSecret,
      tokenEndpoint,
    } = this.options

    const client = new TokenStore(
      {
        axios,
        clientId,
        clientSecret,
        tokenEndpoint,
      },
      tokens,
    )

    client.onRefreshToken((tokens) => {
      this.saveTokensToLocalStorage(tokens)
    })

    return client
  }

  private saveTokensToLocalStorage(tokens: OAuth2ClientTokensWithExpiration | null): void {
    if (tokens === null)
      localStorage.removeItem('tokens')
    else
      localStorage.setItem('tokens', JSON.stringify(tokens))
  }

  private loadTokensFromLocalStorage(): OAuth2ClientTokensWithExpiration | null {
    const tokens = localStorage.getItem('tokens')

    if (tokens === null)
      return null

    return JSON.parse(tokens) as OAuth2ClientTokensWithExpiration
  }

  public getClient(): TokenStore | null {
    return this.client
  }

  private removeClient(): void {
    this.client = null
  }

  public async loginPassword(username: string, password: string): Promise<void> {
    const client = await this.oAuthFactory.loginPassword(username, password)

    const tokens = client.getTokens()

    this.saveTokensToLocalStorage(tokens)
    this.client = this.createClient(tokens)
  }

  public async loginAuthorisation(code: string, state: string, grantType: OAuth2ClientGrantType): Promise<void> {
    const client = await this.oAuthFactory.loginAuthorization(code, state, grantType)

    const tokens = client.getTokens()

    this.saveTokensToLocalStorage(tokens)
    this.client = this.createClient(tokens)
  }

  public logout(): void {
    this.saveTokensToLocalStorage(null)
    this.removeClient()
  }

  public isLoggedIn(): boolean {
    const client = this.getClient()
    return client?.getTokens() != null
  }
}

export async function addAuthorizationHeader(
  oAuthClient: OAuth2VueClient,
  config: InternalAxiosRequestConfig<unknown>,
): Promise<InternalAxiosRequestConfig<unknown>> {
  const client = oAuthClient.getClient()

  if (client === null)
    return config

  try {
    const token = await client.getAccessToken()

    config.headers.Authorization = `Bearer ${token}`
  }
  catch {
    console.warn('Failed to get access token, logging out')
  }

  return config
}
