<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace ZfrLightspeedRetail\OAuth;

use DateTimeImmutable;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Psr\Http\Message\UriInterface;
use RuntimeException;
use ZfrLightspeedRetail\Exception\InvalidStateException;
use ZfrLightspeedRetail\Exception\MissingRequiredScopeException;
use ZfrLightspeedRetail\Exception\UnauthorizedException;
use ZfrLightspeedRetail\OAuth\CredentialStorage\CredentialStorageInterface;
use ZfrLightspeedRetail\OAuth\VerifierStorage\VerifierStorageInterface;
use GuzzleHttp\Utils as GUtils;

/**
 * @author Daniel Gimenes
 */
final class JwtAuthorizationService implements AuthorizationServiceInterface
{
    // @codingStandardsIgnoreStart
    private const LS_ENDPOINT_AUTHORIZE    = 'https://cloud.lightspeedapp.com/auth/oauth/authorize?response_type=code&client_id=%s&scope=%s&state=%s&code_challenge_method=S256&code_challenge=%s';
    private const LS_ENDPOINT_ACCESS_TOKEN = 'https://cloud.lightspeedapp.com/auth/oauth/token';
    private const LS_ENDPOINT_ACCOUNT      = 'https://api.lightspeedapp.com/API/Account.json';
    // @codingStandardsIgnoreEnd

    /**
     * @var CredentialStorageInterface
     */
    private $credentialStorage;

    /**
     * @var VerifierStorageInterface
     */
    private $verifierStorage;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var string
     */
    private $clientId;

    private Configuration $config;

    /**
     * @param CredentialStorageInterface $credentialStorage
     * @param VerifierStorageInterface   $verifierStorage
     * @param ClientInterface            $httpClient
     * @param string                     $clientId
     */
    public function __construct(
        CredentialStorageInterface $credentialStorage,
        VerifierStorageInterface $verifierStorage,
        ClientInterface $httpClient,
        string $clientId,
        Configuration $config
    ) {
        $this->credentialStorage = $credentialStorage;
        $this->verifierStorage   = $verifierStorage;
        $this->httpClient        = $httpClient;
        $this->clientId          = $clientId;
        $this->config            = $config;
    }

    /**
     * 1. Builds an authorization URL that identifies the internal account ID and the requested scope.
     * 2. Store the verification code in verifier storage
     *
     * @param string   $referenceId    Internal account ID (identifies the account in your application)
     * @param string[] $requestedScope Scope requested by your application
     *
     * @return UriInterface
     */
    public function buildAuthorizationUrl(string $referenceId, array $requestedScope): UriInterface
    {
        $state = $this->buildState($referenceId, $requestedScope);

        $code_verifier = self::base64urlEncode(random_bytes(64));
        $code_challenge = self::base64urlEncode(hash('sha256', $code_verifier, true));
        $this->verifierStorage->save(new Verifier($referenceId, $code_verifier));

        return new Uri(sprintf(
            self::LS_ENDPOINT_AUTHORIZE,
            $this->clientId,
            implode('+', $requestedScope),
            $state->toString(),
            $code_challenge
        ));
    }

    /**
     * 1 - Parses and validates the provided state
     * 2 - Exchanges the given authorization code by a token pair (access token + refresh token + verifier)
     * 3 - Validates if the requested scope is satisfied by granted scope
     * 4 - Fetches the Lightspeed Account ID (this is required for all API calls)
     * 5 - Stores Lightspeed Account ID and tokens in credential storage
     *
     * @param string $authorizationCode Temporary authorization code received from authorization server
     * @param string $state             State string received from authorization server
     *
     * @throws InvalidStateException         If the provided state is invalid or expired
     * @throws MissingRequiredScopeException If the granted scope does not satisfy the scope required by your app.
     * @throws UnauthorizedException         If Lightspeed Retail authorization server rejects the provided auth code.
     */
    public function processCallback(string $authorizationCode, string $state): void
    {
        $stateToken = $this->parseState($state);
        $referenceId  = $stateToken->claims()->get('uid');
        $result     = $this->exchangeAuthorizationCode($authorizationCode, $referenceId);

        // TODO: Update to use decoded accessToken to confirm scope
        // Removing as 'scope' is no longer returned by the auth call.
        // $this->guardRequiredScope($stateToken, $result['scope']);

        $accessToken  = $result['access_token'];
        $refreshToken = $result['refresh_token'];
        $lsAccountId  = $this->fetchLightspeedAccountId($accessToken);

        $this->credentialStorage->save(new Credential($referenceId, $lsAccountId, $accessToken, $refreshToken));
    }

    /**
     * @param string $referenceId
     * @param array  $requestedScope
     *
     * @return Token
     */
    private function buildState(string $referenceId, array $requestedScope): Token
    {
        $now = new DateTimeImmutable();

        return $this->config->builder()
            ->issuedAt($now)
            ->expiresAt($now->modify('+ 10 minutes'))
            ->withClaim('uid', $referenceId)
            ->withClaim('scope', $requestedScope)
            ->getToken($this->config->signer(), $this->config->signingKey());
    }

    /**
     * @param string $data the string to encode
     *
     * @return string The encoded data
     */
    public static function base64urlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $state
     *
     * @return Token
     * @throws InvalidStateException
     */
    private function parseState(string $state): Token
    {
        try {
            $token = $this->config->parser()->parse($state);
        } catch (InvalidArgumentException | RuntimeException $exception) {
            throw InvalidStateException::fromInvalidState($state, $exception);
        }

        if (! $this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
            throw InvalidStateException::fromInvalidState($state);
        }

        return $token;
    }

    /**
     * @param string $authorizationCode
     *
     * @return array
     * @throws UnauthorizedException
     */
    private function exchangeAuthorizationCode(string $authorizationCode, string $referenceId): array
    {
        try {
            $response = $this->httpClient->request('POST', self::LS_ENDPOINT_ACCESS_TOKEN, [
                'json' => [
                    'client_id'     => $this->clientId,
                    'client_secret' => $this->config->signingKey()->contents(),
                    'code'          => $authorizationCode,
                    'grant_type'    => 'authorization_code',
                    'code_verifier' => $this->verifierStorage->get($referenceId)->getCode(),
                ],
            ]);
        } catch (ClientException $exception) {
            throw UnauthorizedException::authorizationCodeRejected($authorizationCode);
        }

        return GUtils::jsonDecode((string) $response->getBody(), true);
    }

    /**
     * @param Token  $stateToken
     * @param string $grantedScope
     *
     * @throws MissingRequiredScopeException
     */
    private function guardRequiredScope(Token $stateToken, string $grantedScope): void
    {
        $requestedScope = $stateToken->claims()->get('scope');
        $grantedScope   = explode(' ', $grantedScope);
        $missingScope   = array_diff($requestedScope, $grantedScope);

        if (! empty($missingScope)) {
            throw MissingRequiredScopeException::fromMissingScope($missingScope);
        }
    }

    /**
     * @param string $accessToken
     *
     * @return int
     */
    private function fetchLightspeedAccountId(string $accessToken): int
    {
        $response = $this->httpClient->request('GET', self::LS_ENDPOINT_ACCOUNT, [
            'headers' => ['Authorization' => sprintf('Bearer %s', $accessToken)],
        ]);

        $result = GUtils::jsonDecode((string) $response->getBody(), true);

        return $result['Account']['accountID'];
    }
}
