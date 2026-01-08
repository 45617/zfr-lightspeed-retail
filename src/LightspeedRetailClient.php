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

namespace ZfrLightspeedRetail;

use GuzzleHttp\Client;
use GuzzleHttp\Command\CommandInterface;
use GuzzleHttp\Command\Guzzle\Description;
use GuzzleHttp\Command\Guzzle\Deserializer as GuzzleDeserializer;
use GuzzleHttp\Command\Guzzle\GuzzleClient;
use GuzzleHttp\Command\ResultInterface;
use GuzzleHttp\Command\ServiceClientInterface;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use OutOfBoundsException;
use Psr\Http\Message\ResponseInterface;
use Traversable;
use ZfrLightspeedRetail\OAuth\AuthorizationMiddleware;
use ZfrLightspeedRetail\OAuth\CredentialStorage\CredentialStorageInterface;

use Exception;
use SodiumException;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\Key;
use GuzzleHttp\Psr7\HttpFactory;
use League\Uri\Uri;
use Phpfastcache\CacheManager;

/**
 * HTTP Client used to interact with the Lightspeed Retail API
 *
 * @author Daniel Gimenes
 * @author Michaël Gallego
 * @author Zoltan Szanto
 *
 * @method ResultInterface getAccount()
 *
 * CUSTOMER RELATED METHODS:
 *
 * @method ResultInterface getCustomers(array $args = [])
 * @method ResultInterface getCustomer(array $args = [])
 * @method ResultInterface createCustomer(array $args = [])
 * @method ResultInterface updateCustomer(array $args = [])
 *
 * ITEM RELATED METHODS:
 *
 * @method ResultInterface getItems(array $args = [])
 * @method ResultInterface createItem(array $args = [])
 * @method ResultInterface updateItem(array $args = [])
 *
 * SALE RELATED METHODS:
 *
 * @method ResultInterface getSales(array $args = [])
 * @method ResultInterface getSale(array $args = [])
 *
 * SALE LINE RELATED METHODS:
 *
 * @method ResultInterface getSaleLine(array $args = [])
 *
 * WORKORDER RELATED METHODS:
 *
 * @method ResultInterface getWorkorderStatuses(array $args = [])
 * @method ResultInterface getWorkorderStatus(array $args = [])
 *
 * ITERATOR METHODS:
 *
 * @method Traversable getCustomersIterator(array $args = [])
 * @method Traversable getItemsIterator(array $args = [])
 * @method Traversable getSalesIterator(array $args = [])
 * @method Traversable getWorkorderStatusesIterator(array $args = [])
 */
class LightspeedRetailClient
{
    const LIGHTSPEED_JWKS_ENDPOINT = 'https://cloud.lightspeedapp.com/.well-known/jwks';

    /**
     * @var ServiceClientInterface
     */
    private $serviceClient;

    /**
     * @param ServiceClientInterface $serviceClient
     */
    public function __construct(ServiceClientInterface $serviceClient)
    {
        $this->serviceClient = $serviceClient;
    }

    /**
     * @param CredentialStorageInterface $credentialStorage
     * @param array                      $config
     *
     * @return LightspeedRetailClient
     */
    public static function fromDefaults(CredentialStorageInterface $credentialStorage, array $config): self
    {
        if (empty($config['client_id']) || empty($config['client_secret'])) {
            throw new OutOfBoundsException(
                'Missing "client_id" and "client_secret" config for ZfrLightspeedRetail'
            );
        }

        $handlerStack = HandlerStack::create();

        // HTTP Middleware that avoids throttling
        $handlerStack->push(LeakyBucketMiddleware::wrapped());

        // HTTP Middleware that retries requests according to our retry strategy
        $handlerStack->push(Middleware::retry(new RetryStrategy($config['max_retries'] ?? 3)));

        $httpClient   = new Client(['handler' => $handlerStack, 'timeout' => 60, 'connect_timeout' => 60]);
        $description  = new Description(require __DIR__ . '/ServiceDescription/Lightspeed-Retail-2016.25.php');
        $deserializer = new Deserializer(new GuzzleDeserializer($description, true), $description);
        $clientConfig = [];

        // If a default reference ID is provided in config, we add it as default command param
        if (! empty($config['reference_id'])) {
            $clientConfig['defaults']['referenceID'] = $config['reference_id'];
        }

        $serviceClient = new GuzzleClient($httpClient, $description, null, $deserializer, null, $clientConfig);

        // Command Middleware that handles authorization
        $serviceClient->getHandlerStack()->push(AuthorizationMiddleware::wrapped(
            $credentialStorage,
            $httpClient,
            $config['client_id'],
            $config['client_secret']
        ));

        return new self($serviceClient);
    }

    /**
     * Validate the webhook uri of the current request
     */
    public static function validateWebhookUri(?string $uri = null): bool
    {
        if ($uri == null) {
            // Rebuild the request URL
            $uri = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on'  ? 'https://' : 'http://')
                . $_SERVER['HTTP_HOST']
                // ensure the path starts with a slash
                . '/' . ltrim($_SERVER['REQUEST_URI'], '/');
        }

        // Apply lossless URI normalization, according to RFC-3986
        // See https://en.wikipedia.org/wiki/URI_normalization
        $uri = Uri::createFromString($uri);

        // validate required query parameters are present
        parse_str((string)$uri->getQuery(), $queryParams);
        if (
            !isset($queryParams['signature'])
            || !isset($queryParams['exp'])
            || !isset($queryParams['kid'])
            || !isset($queryParams['alg'])
        ) {
            throw new Exception('Bad Request. Required query parameters are missing.');
        }
        // validate that the signature has not expired
        if ($queryParams['exp'] < time()) {
            throw new Exception('Bad Request. Request signature has expired.');
        }

        // Validate the signature matches the request contents to ensure that the request was initiated by Lightspeed.
        // This can prevent request forgery attacks against your application.

        // extract the signature and remove it from the query
        // The signature is url-safe base64 encoded (RFC-4648), convert to binary
        $signature = (string)$queryParams['signature'];
        unset($queryParams['signature']);
        try {
            $decodedSignature = sodium_base642bin($signature, SODIUM_BASE64_VARIANT_URLSAFE);
        } catch (SodiumException $e) {
            throw new Exception('Bad Request. Request signature could not be decoded. Error:' . $e->getMessage(), 0, $e);
        }

        // sort the remaining query parameters alphabetically, in case the server does not preserve the order
        ksort($queryParams);
        // Rebuild the URI without the signature
        $urlWithoutSignature = $uri->withQuery(http_build_query($queryParams))->__toString();

        // Fetch and cache Lightspeed's public key set, then return the specific key needed to
        // verify this particular request in RSA PEM format
        $publicKeyPem = self::fetchLightspeedPublicKeyForKeyId($queryParams['kid'])->getKeyMaterial();
        // Verify the RS256 signature using the public key provided by Lightspeed
        $signatureMatches = 1 === openssl_verify(
            $urlWithoutSignature,
            $decodedSignature,
            $publicKeyPem,
            OPENSSL_ALGO_SHA256
        );

        if (!$signatureMatches) {
            throw new Exception('Bad Request. Request signature could not be verified. Error: ' . openssl_error_string());
        };
        return true;
    }

    private static function fetchLightspeedPublicKeyForKeyId(string $keyId): Key
    {
        // Create an HTTP client (can be any PSR-7 compatible HTTP client)
        $httpClient = new Client();

        // Create an HTTP request factory (can be any PSR-17 compatible HTTP request factory)
        $httpFactory = new HttpFactory();

        // Create a cache item pool (can be any PSR-6 compatible cache item pool)
        $cacheItemPool = CacheManager::getInstance('files');

        $keySet = new CachedKeySet(
            self::LIGHTSPEED_JWKS_ENDPOINT,
            $httpClient,
            $httpFactory,
            $cacheItemPool,
            60 * 60, // Cache for 1 hour
        );

        return $keySet->offsetGet($keyId);
    }

    /**
     * Directly call a specific endpoint by creating the command and executing it
     *
     * Using __call magic methods is equivalent to creating and executing a single command.
     * It also supports using optimized iterator requests by adding "Iterator" suffix to the command
     *
     * @param string $method
     * @param array  $args
     *
     * @return ResponseInterface|ResultInterface|Traversable
     */
    public function __call(string $method, array $args = [])
    {
        $params = $args[0] ?? [];

        // Allow magic method calls for iterators
        // (e.g. $client->getSalesIterator($internalAccountId, $params))
        if (substr($method, -8) === 'Iterator') {
            $command = $this->serviceClient->getCommand(substr($method, 0, -8), $params);

            return $this->iterateResources($command);
        }

        $result = $this->serviceClient->$method($params);
        // error_log(print_r($result, true));
        return $result['root'] ?? $result;
    }

    /**
     * @param CommandInterface $command
     *
     * @return Traversable
     */
    private function iterateResources(CommandInterface $command): Traversable
    {
        // When using the iterator, we force the maximum number of items per page to 100
        $command['limit']  = 100;

        do {
            $result = $this->serviceClient->execute(clone $command);
            $items = $result['root'];

            // If there's only one item it comes unwrapped. Wrap it in an array
            $reset = reset($items);
            if ($reset && !is_array($reset)) {
                $items = [0 => $items];
            }

            foreach ($items as $item) {
                yield $item;
            }

            // Move to next page by applying the 'after' and 'limit' parameters from "next"
            if ($result['@attributes']['next']) {
                $url = parse_url($result['@attributes']['next']);
                parse_str($url['query'], $output);
                $command['after'] = $output['after'];
                $command['limit'] = $output['limit'];
            }
        } while ($result['@attributes']['next']);
    }
}
