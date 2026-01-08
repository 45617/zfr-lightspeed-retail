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

namespace ZfrLightspeedRetailTest\OAuth;

use DateTimeImmutable;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Traversable;
use ZfrLightspeedRetail\Exception\InvalidStateException;
use ZfrLightspeedRetail\Exception\MissingRequiredScopeException;
use ZfrLightspeedRetail\Exception\UnauthorizedException;
use ZfrLightspeedRetail\OAuth\AuthorizationServiceInterface;
use ZfrLightspeedRetail\OAuth\CredentialStorage\CredentialStorageInterface;
use ZfrLightspeedRetail\OAuth\VerifierStorage\VerifierStorageInterface;
use ZfrLightspeedRetail\OAuth\JwtAuthorizationService;
use ZfrLightspeedRetail\OAuth\Verifier;
use function GuzzleHttp\json_encode as guzzle_json_encode;

/**
 * @author Daniel Gimenes
 */
final class JwtAuthorizationServiceTest extends TestCase
{
    /**
     * @var ObjectProphecy
     */
    private $credentialStorage;

    /**
     * @var ObjectProphecy
     */
    private $verifierStorage;

    /**
     * @var ObjectProphecy
     */
    private $httpClient;

    /**
     * @var AuthorizationServiceInterface
     */
    private $authorizationService;

    public function setUp(): void
    {
        $this->credentialStorage = $this->prophesize(CredentialStorageInterface::class);
        $this->verifierStorage   = $this->prophesize(VerifierStorageInterface::class);
        $this->httpClient        = $this->prophesize(ClientInterface::class);

        $this->authorizationService = new JwtAuthorizationService(
            $this->credentialStorage->reveal(),
            $this->verifierStorage->reveal(),
            $this->httpClient->reveal(),
            new Sha256(),
            '123',
            'abc123'
        );
    }

    public function testBuildsAuthorizationUrl()
    {
        $referenceId      = 'omc-demo.myshopify.com';
        $requestedScope   = ['employee:inventory', 'employee:reports'];
        $authorizationUrl = $this->authorizationService->buildAuthorizationUrl($referenceId, $requestedScope);

        $this->assertSame('https', $authorizationUrl->getScheme());
        $this->assertSame('cloud.lightspeedapp.com', $authorizationUrl->getHost());
        $this->assertSame('/auth/oauth/authorize', $authorizationUrl->getPath());

        $query = Query::parse($authorizationUrl->getQuery(), false);

        $this->assertSame('code', $query['response_type']);
        $this->assertSame('123', $query['client_id']);
        $this->assertSame('employee:inventory+employee:reports', $query['scope']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $code_challenge = $query['code_challenge'];
        $this->assertNotEmpty($code_challenge);

        // Save verifier to storage
        $this->verifierStorage->save(Argument::that(
            function ($verifier) use ($referenceId, $code_challenge) {
                $this->assertSame($verifier->getReferenceId(), $referenceId);
                $code = $verifier->getCode();
                return $code_challenge == JwtAuthorizationService::base64urlEncode(hash('sha256', $code, true));
            }
        ))->shouldBeCalled();

        $state = (new Parser())->parse($query['state']);

        $this->assertFalse($state->isExpired(new DateTimeImmutable()));
        $this->assertTrue($state->isExpired(new DateTimeImmutable('+ 11 minutes')));
        $this->assertTrue($state->verify(new Sha256(), InMemory::plainText('abc123')));
        $this->assertSame($referenceId, $state->getClaim('uid'));
        $this->assertSame($requestedScope, $state->getClaim('scope'));
    }

    public function testExchangesAndStoresTokens()
    {
        // Prepare authorization URL
        $referenceId      = 'omc-demo.myshopify.com';
        $requestedScope   = ['employee:inventory', 'employee:reports'];
        $authorizationUrl = $this->authorizationService->buildAuthorizationUrl($referenceId, $requestedScope);

        // Mocked auth code + state returned by Lightspeed Authorization Server
        $authorizationCode = '123456789';
        $state             = Query::parse($authorizationUrl->getQuery(), false)['state'];
        $code_verifier     = 'foo';

        // Get code verifier from storage
        $this->verifierStorage->get(
            $referenceId
        )->shouldBeCalled()->willReturn(
            new Verifier($referenceId, $code_verifier)
        );

        // Exchanges code for tokens
        $this->httpClient->request('POST', 'https://cloud.lightspeedapp.com/auth/oauth/token', [
            'json' => [
                'client_id'     => '123',
                'client_secret' => 'abc123',
                'code'          => $authorizationCode,
                'grant_type'    => 'authorization_code',
                'code_verifier' => $code_verifier,
            ],
        ])->shouldBeCalled()->willReturn(
            new Response(200, [], Utils::streamFor(guzzle_json_encode([
                'access_token'  => 'foo',
                'refresh_token' => 'bar',
            ])))
        );

        // Fetches account ID
        $this->httpClient->request('GET', 'https://api.lightspeedapp.com/API/Account.json', [
            'headers' => ['Authorization' => 'Bearer foo'],
        ])->shouldBeCalled()->willReturn(
            new Response(200, [], Utils::streamFor(guzzle_json_encode([
                'Account' => ['accountID' => '123456'],
            ])))
        );

        // Save credential to storage
        $this->credentialStorage->save(Argument::allOf(
            Argument::which('getReferenceId', $referenceId),
            Argument::which('getLightspeedAccountId', '123456'),
            Argument::which('getAccessToken', 'foo'),
            Argument::which('getRefreshToken', 'bar')
        ))->shouldBeCalled();

        $this->authorizationService->processCallback($authorizationCode, $state);
    }

    /**
     * @dataProvider provideInvalidStates
     *
     * @param string $state
     */
    public function testThrowsExceptionIfInvalidState(string $state)
    {
        $this->expectException(InvalidStateException::class);
        $this->expectExceptionMessage("Invalid state received ($state)");

        $this->authorizationService->processCallback('123456789', $state);
    }

    public function testThrowsExceptionIfRejectAuthCode()
    {
        $referenceId = 'omc-demo.myshopify.com';
        $authUrl = $this->authorizationService->buildAuthorizationUrl(
            $referenceId,
            ['employee:all']
        );

        $validState        = Query::parse($authUrl->getQuery(), false)['state'];
        $authorizationCode = '123456';
        $code_verifier     = 'foo';

        // Get code verifier from storage
        $this->verifierStorage->get(
            $referenceId
        )->shouldBeCalled()->willReturn(
            new Verifier($referenceId, $code_verifier)
        );

        $this->httpClient->request('POST', 'https://cloud.lightspeedapp.com/auth/oauth/token', [
            'json' => [
                'client_id'     => '123',
                'client_secret' => 'abc123',
                'code'          => $authorizationCode,
                'grant_type'    => 'authorization_code',
                'code_verifier' => $code_verifier,
            ],
        ])->shouldBeCalled()->willThrow(
            new ClientException('Boom!', new Request('GET', 'https://cloud.lightspeedapp.com/auth/oauth/token'), new Response())
        );

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization code "123456" was rejected by Lightspeed Authorization Server');

        $this->authorizationService->processCallback($authorizationCode, $validState);
    }

    // TODO: Update to use decoded accessToken to confirm scope
    // Removing as scope is no longer returned by the auth call.
    public function throwsExceptionIfMissingRequiredScope()
    {
        $referenceId = 'omc-demo.myshopify.com';
        $authUrl = $this->authorizationService->buildAuthorizationUrl(
            $referenceId,
            ['employee:register', 'employee:inventory', 'employee:reports']
        );

        $validState        = Query::parse($authUrl->getQuery(), false)['state'];
        $authorizationCode = '123456';
        $code_verifier     = 'foo';

        // Get code verifier from storage
        $this->verifierStorage->get(
            $referenceId
        )->shouldBeCalled()->willReturn(
            new Verifier($referenceId, $code_verifier)
        );

        // Exchanges code for tokens
        $this->httpClient->request('POST', 'https://cloud.lightspeedapp.com/auth/oauth/token', [
            'json' => [
                'client_id'     => '123',
                'client_secret' => 'abc123',
                'code'          => $authorizationCode,
                'grant_type'    => 'authorization_code',
                'code_verifier' => $code_verifier,
            ],
        ])->shouldBeCalled()->willReturn(
            new Response(200, [], Utils::streamFor(guzzle_json_encode([
                'access_token'  => 'foo',
                'scope'         => 'employee:inventory systemuserid:393608', // Missing "register" and "reports"
                'refresh_token' => 'bar',
            ])))
        );

        $this->expectException(MissingRequiredScopeException::class);
        $this->expectExceptionMessage(
            'The following scope is required but was not granted: employee:register, employee:reports'
        );

        $this->authorizationService->processCallback('123456', $validState);
    }

    public function provideInvalidStates(): Traversable
    {
        yield 'Non JWT' => ['foobar'];
        yield 'Undecodable' => ['foo.bar.baz'];

        // @codingStandardsIgnoreStart
        yield 'Expired' => ['eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0ODU3NTA3MDYsImV4cCI6MTQ4NTc1MTMwNiwidWlkIjoib21jLWRlbW8ubXlzaG9waWZ5LmNvbSIsInNjb3BlIjpbImVtcGxveWVlOmFsbCJdfQ.lIVA_z1_bGHne_ooFJiIzHmwd5dxZ3xi8kDEy7MHfMU'];
        // @codingStandardsIgnoreEnd

        // Create another authorization service to sign with a different key
        $authUrl = (new JwtAuthorizationService(
            $this->prophesize(CredentialStorageInterface::class)->reveal(),
            $this->prophesize(VerifierStorageInterface::class)->reveal(),
            $this->prophesize(ClientInterface::class)->reveal(),
            new Sha256(),
            '123',
            'foobar' // Different secret
        ))->buildAuthorizationUrl('omc-demo.myshopify.com', ['employee:all']);

        $usignedState =  Query::parse($authUrl->getQuery(), false)['state'];

        yield 'Unsigned' => [$usignedState];
    }
}
