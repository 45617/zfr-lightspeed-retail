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

/**
 * @author 45617
 */
final class Verifier
{
    /**
     * @var string
     */
    private $referenceId;

    /**
     * @var string
     */
    private $code;

    /**
     * @param string $referenceId
     * @param string $code
     */
    public function __construct(
        string $referenceId,
        string $code
    ) {
        $this->referenceId = $referenceId;
        $this->code        = $code;
    }

    /**
     * @param array $data
     *
     * @return Verifier
     */
    public static function fromArray(array $data): self
    {
        return new self(
            $data['reference_id'],
            $data['code'],
        );
    }

    /**
     * @return array
     */
    public function toArray(): array
    {
        return [
            'reference_id' => $this->referenceId,
            'code'         => $this->code,
        ];
    }

    /**
     * @return string
     */
    public function getReferenceId(): string
    {
        return $this->referenceId;
    }

    /**
     * @return string
     */
    public function getCode(): string
    {
        return $this->code;
    }
}
