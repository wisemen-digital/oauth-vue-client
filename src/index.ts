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

export class OAuth2VueClient {
  private client: TokenStore | null = null
  private oAuthFactory: OAuth2Client

  constructor(private readonly options: OAuth2VueClientOptions) {
    const {
      clientId,
      axios,
      clientSecret,
      tokenEndpoint,
    } = options

    this.oAuthFactory = new OAuth2Client({
      clientId,
      axios,
      clientSecret,
      tokenEndpoint,
    })

    const tokens = this.loadTokensFromLocalStorage()

    if (tokens !== null) {
      this.client = this.createClient(tokens)
    }
  }

  private createClient(tokens: OAuth2ClientTokensWithExpiration): TokenStore {
    const {
      clientId,
      axios,
      clientSecret,
      tokenEndpoint,
    } = this.options

    const client = new TokenStore(
      {
        clientId,
        axios,
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
    }
    else {
      localStorage.setItem('tokens', JSON.stringify(tokens))
    }
  }

  public getClient(): TokenStore | null {
    return this.client
  }

  public isLoggedIn(): boolean {
    if (this.options.isMock === true) {
      return true
    }

    const client = this.getClient()

    return client?.getTokens() != null
  }

  public async loginAuthorisation(code: string, state: string, grantType: OAuth2ClientGrantType): Promise<void> {
    if (this.options.isMock === true) {
      return Promise.resolve()
    }

    const client = await this.oAuthFactory.loginAuthorization(code, state, grantType)

    const tokens = client.getTokens()

    this.saveTokensToLocalStorage(tokens)
    this.client = this.createClient(tokens)
  }

  public async loginPassword(username: string, password: string): Promise<void> {
    if (this.options.isMock === true) {
      return Promise.resolve()
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
