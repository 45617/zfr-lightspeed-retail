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

return [
    'name'        => 'LightspeedRetail',
    'description' => 'Lightspeed Retail API',
    'baseUri'     => 'https://api.lightspeedapp.com/API/V3/',
    'operations'  => [
        'GetAccount' => [
            'httpMethod'    => 'GET',
            'uri'           => 'https://api.lightspeedapp.com/API/Account.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Account',
            ],
        ],
        'GetShops' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Shop.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Shop',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        /**
         * --------------------------------------------------------------------------------
         * CUSTOMER RELATED METHODS
         *
         * DOC: http://developers.lightspeedhq.com/retail/endpoints/Customer/
         * --------------------------------------------------------------------------------
         */

        'GetCustomers' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Customer.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Customer',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        'GetCustomersAttributes' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Customer.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => '@attributes',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetCustomer' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Customer/{customerID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Customer',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'customerID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'CreateCustomer' => [
            'httpMethod'    => 'POST',
            'uri'           => 'Account/{accountID}/Customer.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Customer',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'firstName' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'lastName' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'dob' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'Contact' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
                'CustomFieldValues' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
            ],
        ],

        'UpdateCustomer' => [
            'httpMethod'    => 'PUT',
            'uri'           => 'Account/{accountID}/Customer/{customerID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Customer',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'customerID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'firstName' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'lastName' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'dob' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'Contact' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
                'CustomFieldValues' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
            ],
        ],

        /**
         * --------------------------------------------------------------------------------
         * ITEM RELATED METHODS
         *
         * DOC: http://developers.lightspeedhq.com/retail/endpoints/Item/
         * --------------------------------------------------------------------------------
         */

        'GetItems' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Item.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Item',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        'GetItemsAttributes' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Item.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => '@attributes',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'CreateItem' => [
            'httpMethod'    => 'POST',
            'uri'           => 'Account/{accountID}/Item.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Item',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'description' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'ean' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'customSku' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'manufacturerSku' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'Prices' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
                'Images' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
            ],
        ],

        'UpdateItem' => [
            'httpMethod'    => 'PUT',
            'uri'           => 'Account/{accountID}/Item/{itemID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Item',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'itemID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'description' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'ean' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'customSku' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'manufacturerSku' => [
                    'location' => 'json',
                    'type'     => 'string',
                    'required' => false,
                ],
                'Prices' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
                'Images' => [
                    'location' => 'json',
                    'type'     => 'object',
                    'required' => false,
                ],
            ],
        ],

        'GetCatalogVendorItem' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/CatalogVendorItem/{catalogVendorItemID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'CatalogVendorItem',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'catalogVendorItemID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetCatalogVendorItems' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/CatalogVendorItem.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'CatalogVendorItem',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetCatalogVendorItem' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/CatalogVendorItem/{catalogVendorItemID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'CatalogVendorItem',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'catalogVendorItemID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetVendors' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Vendor.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Vendor',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        /**
         * --------------------------------------------------------------------------------
         * SALE RELATED METHODS
         *
         * DOC: http://developers.lightspeedhq.com/retail/endpoints/Sale/
         * --------------------------------------------------------------------------------
         */

        'GetSales' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Sale.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Sale',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        'GetSalesAttributes' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Sale.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => '@attributes',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'archived' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'boolean',
                ],
                'timeStamp' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
                'orderby' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        'GetSale' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Sale/{saleID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'Sale',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'saleID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        /**
         * --------------------------------------------------------------------------------
         * SALE LINE RELATED METHODS
         *
         * DOC: https://developers.lightspeedhq.com/retail/endpoints/SaleLine/
         * --------------------------------------------------------------------------------
         */
        'GetSaleLine' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/SaleLine/{saleLineID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'SaleLine',
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'saleLineID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetSaleLines' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/SaleLine.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key' => 'SaleLine',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'load_relations' => [
                    'location' => 'query',
                    'type'     => 'string',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetCategories' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Category.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Category',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'limit' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],
                'offset' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'integer',
                ],

            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        /**
         * --------------------------------------------------------------------------------
         * DISPLAYTEMPLATE RELATED METHODS
         *
         * DOC: https://developers.lightspeedhq.com/retail/endpoints/DisplayTemplate-Workorder/
         * --------------------------------------------------------------------------------
         */
        'GetDisplayTemplateWorkorder' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/DisplayTemplate/Workorder/{workorderID}.html',
            'responseModel' => 'HTML',
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'workorderID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'template' => [
                    'location' => 'query',
                    'required' => false,
                    'type'     => 'string',
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],
        /**
         * --------------------------------------------------------------------------------
         * WORKORDER RELATED METHODS
         *
         * DOC: https://developers.lightspeedhq.com/retail/endpoints/Workorder/
         * --------------------------------------------------------------------------------
         */
        'GetWorkorder' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Workorder/{workorderID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Workorder',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'workorderID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetWorkorders' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/Workorder.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'Workorder',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetWorkorderStatus' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/WorkorderStatus/{workorderStatusID}.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'WorkorderStatus',
                'is_collection' => false,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
                'workorderStatusID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

        'GetWorkorderStatuses' => [
            'httpMethod'    => 'GET',
            'uri'           => 'Account/{accountID}/WorkorderStatus.json',
            'responseModel' => 'GenericModel',
            'data'          => [
                'root_key'      => 'WorkorderStatus',
                'is_collection' => true,
            ],
            'parameters' => [
                'accountID' => [
                    'location' => 'uri',
                    'type'     => 'integer',
                    'required' => false,
                ],
            ],
            'additionalParameters' => [
                'location' => 'query',
            ],
        ],

    ],

    'models' => [
        'GenericModel' => [
            'type'                 => 'object',
            'additionalProperties' => [
                'location' => 'json',
            ],
        ],
        'HTML' => [
            'type' => 'array',
            'location' => 'body',
        ],
    ],
];
