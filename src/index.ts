import type {
  AxiosStatic,
  InternalAxiosRequestConfig,
} from 'axios'

import type {
  OAuth2ClientGrantType,
  OAuth2ClientTokensWithExpiration,
} from './oAuthClient'
import { OAuth2Client, TokenStore } from './oAuthClient'

interface OAuth2VueClientOptions {
  clientId: string
  isMock?: boolean
  axios: AxiosStatic
  clientSecret: string
  scopes?: string[]
  tokenEndpoint: string
}

const MOCK_TOKENS: OAuth2ClientTokensWithExpiration = {
  expires_at: 1000000,
  access_token: 'fake_access_token',
  expires_in: 1000000,
  refresh_token: 'fake_refresh_token',
  scope: '',
  token_type: 'fake_token',
}

export class OAuth2VueClient {
  private client: TokenStore | null = null
  private oAuthFactory: OAuth2Client

  constructor(private readonly options: OAuth2VueClientOptions) {
    this.oAuthFactory = new OAuth2Client({
      clientId: options.clientId,
      isMock: options.isMock,
      axios: options.axios,
      clientSecret: options.clientSecret,
      scopes: options.scopes,
      tokenEndpoint: options.tokenEndpoint,
    })

    const tokens = this.loadTokensFromLocalStorage()

    if (tokens !== null) {
      this.client = this.createClient(tokens)
    }
  }

  private createClient(tokens: OAuth2ClientTokensWithExpiration): TokenStore {
    const client = new TokenStore(
      {
        clientId: this.options.clientId,
        isMock: this.options.isMock,
        axios: this.options.axios,
        clientSecret: this.options.clientSecret,
        scopes: this.options.scopes,
        tokenEndpoint: this.options.tokenEndpoint,
      },
      tokens,
    )

    client.onRefreshToken((tokens) => {
      this.saveTokensToLocalStorage(tokens)
    })

    return client
  }

  private loadTokensFromLocalStorage(): OAuth2ClientTokensWithExpiration | null {
    const tokens = localStorage.getItem('tokens')

    if (tokens === null) {
      return null
    }

    return JSON.parse(tokens) as OAuth2ClientTokensWithExpiration
  }

  private removeClient(): void {
    this.client = null
  }

  private saveTokensToLocalStorage(tokens: OAuth2ClientTokensWithExpiration | null): void {
    if (tokens === null) {
      localStorage.removeItem('tokens')

      return
    }

    localStorage.setItem('tokens', JSON.stringify(tokens))
  }

  public getClient(): TokenStore | null {
    return this.client
  }

  public isLoggedIn(): boolean {
    const accessToken = this.loadTokensFromLocalStorage()?.access_token

    if (this.options.isMock === true && accessToken === MOCK_TOKENS.access_token) {
      return true
    }

    const client = this.getClient()

    return client?.getTokens() != null
  }

  public async loginAuthorisation(code: string, state: string, grantType: OAuth2ClientGrantType): Promise<void> {
    if (this.options.isMock === true) {
      this.saveTokensToLocalStorage(MOCK_TOKENS)

      return
    }

    const client = await this.oAuthFactory.loginAuthorization(code, state, grantType)

    const tokens = client.getTokens()

    this.saveTokensToLocalStorage(tokens)
    this.client = this.createClient(tokens)
  }

  public async loginPassword(username: string, password: string): Promise<void> {
    if (this.options.isMock === true) {
      this.saveTokensToLocalStorage(MOCK_TOKENS)

      return
    }

    const client = await this.oAuthFactory.loginPassword(username, password)

    const tokens = client.getTokens()

    this.saveTokensToLocalStorage(tokens)
    this.client = this.createClient(tokens)
  }

  public logout(): void {
    this.saveTokensToLocalStorage(null)
    this.removeClient()
  }
}

export async function addAuthorizationHeader(
  oAuthClient: OAuth2VueClient,
  config: InternalAxiosRequestConfig<unknown>,
): Promise<InternalAxiosRequestConfig<unknown>> {
  const client = oAuthClient.getClient()

  if (client === null) {
    return config
  }

  try {
    const token = await client.getAccessToken()

    config.headers.Authorization = `Bearer ${token}`
  }
  catch {
    console.warn('Failed to get access token, logging out')
  }

  return config
}
