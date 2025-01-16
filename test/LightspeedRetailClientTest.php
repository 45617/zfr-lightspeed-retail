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

namespace ZfrLightspeedRetailTest;

use GuzzleHttp\Command\Command;
use GuzzleHttp\Command\Result;
use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use ZfrLightspeedRetail\LightspeedRetailClient;
use ZfrLightspeedRetail\OAuth\CredentialStorage\CredentialStorageInterface;
use ZfrLightspeedRetailTest\TestAsset\ServiceClientInterface;

/**
 * @author Daniel Gimenes
 */
final class LightspeedRetailClientTest extends TestCase
{
    public function testCreatesFromDefaults()
    {
        $storage = $this->prophesize(CredentialStorageInterface::class);

        LightspeedRetailClient::fromDefaults($storage->reveal(), [
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);
    }

    public function testThrowsExceptionIfMissingRequiredConfig()
    {
        $storage = $this->prophesize(CredentialStorageInterface::class);

        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Missing "client_id" and "client_secret" config for ZfrLightspeedRetail');

        LightspeedRetailClient::fromDefaults($storage->reveal(), []);
    }

    public function testForwardsMagicMethodCalls()
    {
        $serviceClient  = $this->prophesize(ServiceClientInterface::class);
        $lsClient       = new LightspeedRetailClient($serviceClient->reveal());
        $expectedResult = new Result(['message' => 'sucess']);

        $serviceClient->doSomething(['foo' => 'bar'])->shouldBeCalled()->willReturn($expectedResult);

        $this->assertSame($expectedResult, $lsClient->doSomething(['foo' => 'bar']));
    }

    public function testIteratesResources()
    {
        $serviceClient = $this->prophesize(ServiceClientInterface::class);
        $lsClient      = new LightspeedRetailClient($serviceClient->reveal());

        // Fetches the command
        $serviceClient->getCommand('getSales', ['foo' => 'bar'])->shouldBeCalled()->willReturn(
            new Command('getSales', ['foo' => 'bar'])
        );

        // offset = 100
        $serviceClient->execute(Argument::allOf(
            Argument::withEntry('foo', 'bar'),
            Argument::withEntry('limit', 100),
            Argument::withEntry('after', 'a')
        ))->shouldBeCalled()->willReturn(
            TestResult::from(array_fill(0, 100, true), 'b')
        );

        // offset = 200
        $serviceClient->execute(Argument::allOf(
            Argument::withEntry('foo', 'bar'),
            Argument::withEntry('limit', 100),
            Argument::withEntry('after', 'b')
        ))->shouldBeCalled()->willReturn(
            TestResult::from(array_fill(0, 50, true))
        );

        // offset = 0 // moving this one to the bottom to avoid endless loop in test
        $serviceClient->execute(Argument::allOf(
            Argument::withEntry('foo', 'bar'),
        ))->shouldBeCalled()->willReturn(
            TestResult::from(array_fill(0, 100, true), 'a')
        );

        $result = $lsClient->getSalesIterator(['foo' => 'bar']);

        $this->assertSame(array_fill(0, 250, true), iterator_to_array($result));
    }
}
