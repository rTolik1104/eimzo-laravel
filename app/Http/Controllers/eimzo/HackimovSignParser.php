<?php

/** @noinspection PhpUndefinedMethodInspection PhpUnused */

/***************************************************************************************************************************************************************************
 * Разработчик Хакимов Александр https://github.com/hackimov                                                                                                               *
 * Данный класс занимается получением данных из подписи формата pkcs7 ГНК РУз.                                                                                             *
 * Подпись расшифровывается с помощью phpseclib из X509 вытаскивается BER формат далее декодируется через ASN1                                                             *
 * Существует ещё дофига OID политик, можно их дополнить в маппинге но я использовал только самые нужные.                                                                  *
 *                                                                                                                                                                         *
 * Работа библиотеки зависит от дополнительной библиотеки PhpSecLib (Библиотека работы с ASN1 и пр. по умолчанию есть во всех композерах).                                 *
 * Для корректной работы нужно всего лишь правильно указать путь до библиотеки в use phpseclib\File\ASN1, т.к. библиотека может распологаться у вас в другом неймспейсе.   *
 * Функционал являющийся ядром системы.                                                                                                                                    *
 *                                                                                                                                                                         *
 * namespace App\Http\Controllers\API\eimzo неймспейс либы указан для нашего проекта, для своего проекта можете выставить свой неймспейс откуда вы и будете вызывать либу. *
 * Результирующие методы имеют snake_case                                                                                                                                  *
 *                                                                                                                                                                         *
 *                                                                                                                                                                         *
 * Примеры использования:                                                                                                                                                  *
 * <?php                                                                                                                                                                   *
 *                                                                                                                                                                         *
 * use App\Http\Controllers\API\eimzo\HackimovSignParser;                                                                                                                  *
 *                                                                                                                                                                         *
 * $signature = HackimovSignParser::signParse($sign);                                                                                                                     *
 * var_dump($signature);                                                                                                                                                   *
 * $signature = HackimovSignParser::isSignature($sign);                                                                                                                   *
 * var_dump($signature);                                                                                                                                                   *
 * $signature = HackimovSignParser::lastByDate($sign);                                                                                                                   *
 * var_dump($signature);                                                                                                                                                   *
 ***************************************************************************************************************************************************************************/

namespace App\Http\Controllers\eimzo;

use DateTime;
use Exception;
use phpseclib3\File\ASN1;

class HackimovSignParser
{
    /**
     * @timezeone присваивается нужный часовой пояс, т.к. подпись не содержит в себе перевод времени на нужный часовой пояс, следовательно для Ташкента это +5 GMT
     * @date_format формат дат, в котором вы будете получать результирующие значения времени
     */
    protected static $timezone = 'Asia/Tashkent';
    protected static $dateFormat = 'Y-m-d H:i:s';
    /**
     * @var string OID политик используемые в маппинге
     */
    protected static $personFullNameOid = '2.5.4.3';
    protected static $personSurnameOid   = '2.5.4.4';
    protected static $companyCountryOid  = '2.5.4.6';
    protected static $companyAreaOid     = '2.5.4.7';
    protected static $companyCityOid     = '2.5.4.8';
    protected static $companyNameOid     = '2.5.4.10';
    protected static $personPositionOid  = '2.5.4.12';
    protected static $companyTypeOid     = '2.5.4.15';
    protected static $personNameOid      = '2.5.4.41';
    protected static $companyTinOid      = '1.2.860.3.16.1.1';
    protected static $personPinOid       = '1.2.860.3.16.1.2';
    protected static $certifirdByOid     = '1.2.840.113549.1.1.11';
    protected static $emailOid            = '1.2.840.113549.1.9.1';
    protected static $signingTimeOid     = '1.2.840.113549.1.9.5';
    protected static $personTinOid       = '0.9.2342.19200300.100.1.1';


    /**
     * @param string $sign
     * @return array|bool
     * Возвращает подпись и всех подписантов содержащихся в подписи, используя mapping выдёргивает нужные OID политик для физических и юридических лиц
     */
    public static function signParse(string $sign)
    {
        try {
            $decoded = self::signToArray($sign);
            if (isset($decoded[0])) {
                $decoded = $decoded[0];
            } else {
                return false;
            }

            if (isset($decoded['content']['0']['content']) && $decoded['content']['0']['content'] === '1.2.840.113549.1.7.2') {
                $pkcs7InfoD = $decoded['content']['1']['content'];

                if(isset($pkcs7InfoD['0']['content']['2']['content']['1']['content']['0']['content']) && $pkcs7InfoD['0']['content']['2']['content']['1']['content']['0']['content']){
                    $signatureData = $pkcs7InfoD['0']['content']['2']['content']['1']['content']['0']['content'];
                }
                elseif(isset($pkcs7InfoD['0']['content']['2']['content']['0']['content']) && $pkcs7InfoD['0']['content']['2']['content']['0']['content']){
                    $signatureData = $pkcs7InfoD['0']['content']['2']['content']['0']['content'];
                }

                $signersData = [];
                // тут из всего г-на мы получаем нужные подписи по следующей схеме (плюсами обосначены нужные элементы для парсинга) т.е. нам нужен только каждый 3-й элемент
                // 0 1 2 3 4 5 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
                // + - - + - - + - - +  -  -  +  -  -  +  -  -  +  -  -  +  -  -  +  -  -  +  -  -

                $signIterator = 0;
                $signersContentCount = count($pkcs7InfoD['0']['content']['3']['content']);
                for ($i=0; $i<$signersContentCount; $i+=3) {
                    $signer = $pkcs7InfoD['0']['content']['3']['content'][$i];

                    // получаем даты согласно маппингу
                    if ($pkcs7InfoD['0']['content']['4']['content']['0']['content']['3']['content']['1']['content']['0']['content'] === self::$signingTimeOid) {
                        $keyInner['signed_at']      = $pkcs7InfoD['0']['content']['4']['content'][$signIterator]['content']['3']['content']['1']['content']['1']['content']['0']['content'];
                    }

                    // кто сертифицировал
                    if ($pkcs7InfoD['0']['content']['4']['content']['0']['content']['1']['content']['0']['content']['0']['content']['0']['content']['0']['content'] === self::$personFullNameOid) {
                        $keyInner['certified_by'] = $pkcs7InfoD['0']['content']['4']['content'][$signIterator]['content']['1']['content']['0']['content']['0']['content']['0']['content']['1']['content'];
                    }

                    // получаем емаил согласно маппингу
                    if ($pkcs7InfoD['0']['content']['3']['content']['0']['content']['0']['content']['5']['content']['0']['content']['0']['content']['0']['content'] === self::$emailOid) {
                        $keyInner['email'] = $pkcs7InfoD['0']['content']['3']['content'][$signIterator]['content']['0']['content']['5']['content']['0']['content']['0']['content']['1']['content'];
                    }

                    $signer = $signer['content']['0']['content'];
                    unset($signer['0'],$signer['2'],$signer['3']);
                    $signer = array_values($signer);

                    if (is_object($signer['0']['content'])) {
                        $keyInner['key_id'] = dechex((int)$signer['0']['content']->toString(true));
                    }

                    if (is_object($signer['0']['content'])) {
                        $keyInner['key_inc'] = $signer['0']['content']->toString(true);
                    }

                    if ($signer['1']['type'] === 16) {
                        $keyInner['key_start'] = $signer['1']['content']['0']['content'];
                        $keyInner['key_stop']  = $signer['1']['content']['1']['content'];
                    }

                    if ($signer['2']['type'] === 16) {
                        foreach ($signer['2']['content'] as $oidData) {
                            if (isset($oidData['content']['0']['content']['1']['content'], $oidData['content']['0']['content']['0']['content'])) {
                                if ($oidData['content']['0']['content']['0']['content'] === self::$personFullNameOid) {
                                    $keyInner['person_full_name'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$personNameOid) {
                                    $keyInner['person_name'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$personSurnameOid) {
                                    $keyInner['person_surname'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyNameOid) {
                                    $keyInner['company_name'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyAreaOid) {
                                    $keyInner['company_area'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyCityOid) {
                                    $keyInner['company_city'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyCountryOid) {
                                    $keyInner['company_country'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$personTinOid) {
                                    $keyInner['person_tin'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$personPositionOid) {
                                    $keyInner['person_position'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyTinOid) {
                                    $keyInner['company_tin'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$companyTypeOid) {
                                    $keyInner['company_type'] = $oidData['content']['0']['content']['1']['content'];
                                }

                                if ($oidData['content']['0']['content']['0']['content'] === self::$personPinOid) {
                                    $keyInner['person_pin'] = $oidData['content']['0']['content']['1']['content'];
                                }
                            }
                        }
                        $keyInner['signed_string'] = $signatureData;
                    }

                    // преобразование объектов времени с указанием таймзоны +5 GMT и перевод в человечески понятный формат даты
                    $keyRandomDates[]     = self::dateConfigure($keyInner['signed_at']);
                    $keyInner['key_start'] = self::dateConfigure($keyInner['key_start']);
                    $keyInner['key_stop']  = self::dateConfigure($keyInner['key_stop']);

                    unset($keyInner['signed_at']);
                    $signersData[] = $keyInner;
                    unset($keyInner);
                    $signIterator++;
                }

                usort($keyRandomDates, ['self','CompareByTimeStamp']);
                $sortedDates = array_reverse($keyRandomDates);
                $forCount = count($sortedDates);
                for ($it = 0; $it<$forCount; $it++) {
                    $signersData[$it]['signed_at'] = $sortedDates[$it];
                    $signersData[$it]['signature_verified'] = self::inRange($signersData[$it]['key_start'], $signersData[$it]['signed_at'], $signersData[$it]['key_stop']);
                }
            }

            /** @noinspection all */
            return $signersData ?? false;
        } catch (Exception $exception) {
            return false;
        }
    }

    /**
     * @param string $sign
     * @return bool
     * Проверяет подпись ли это, возвращает true если это подпись. Если это какакая то дичь, возвращает false
     */
    public static function isSignature(string $sign): bool
    {
        try {
            if (is_array(self::signToArray($sign))) {
                return true;
            }
            return false;
        } catch (Exception $exception) {
            return false;
        }
    }

    /**
     * @param string $sign
     * @return array|bool|mixed
     * Получает последнюю по времени подпись (кто подписал последний, требуется для отображения того или иного подписанта)
     */
    public static function lastByDate(string $sign)
    {
        try {
            $signersData = self::signParse($sign);
            if ($signersData === false) {
                return $signersData;
            }

            $maxData = 0;
            foreach ($signersData as $signerData) {
                if (strtotime($signerData['signed_at']) > $maxData) {
                    $maxData = strtotime($signerData['signed_at']);
                    $lastSignature = $signerData;
                }
            }
            if (!isset($lastSignature)) {
                return false;
            }
            return $lastSignature;
        } catch (Exception $exception) {
            return false;
        }
    }

    /**
     * @param $str
     * @return bool|string
     * Вытаскивает Base64 Encoding Result из base64 если та успешно прошла валидацию
     */
    protected static function hackimovExtractBER($str)
    {
        $temp = preg_replace('#-+[^-]+-+#', '', $str);
        $temp = str_replace(["\r", "\n", ' '], '', $temp);
        // если удалось декодировать base64 запиши туда декодированный base64 иначе запиши false
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;
        // если декодирование base64 прошло неуспешно и в переменную записалось значение false возвращаем исходную строку
        return $temp !== false ? $temp : $str;
    }

    /**
     * @param $sign
     * @return mixed
     * Переводит подпись в многомерный неразобранный массив без маппинга
     */
    protected static function signToArray($sign)
    {
        $ber  = self::hackimovExtractBER($sign);
        return ASN1::decodeBER($ber);
    }

    /**
     * @param $time1
     * @param $time2
     * @return int
     * Сортирует даты по времени, по убыванию
     */
    protected static function compareByTimeStamp($time1, $time2): int
    {
        if (strtotime($time1) < strtotime($time2)) {
            return 1;
        }
        if (strtotime($time1) > strtotime($time2)) {
            return -1;
        }
        return 0;
    }

    protected static function inRange($startTime, $currentTime, $stopTime): bool
    {
        $format = 'Y-m-d H:i:s';
        $startTime   = DateTime::createFromFormat($format, $startTime)->getTimestamp();
        $currentTime = DateTime::createFromFormat($format, $currentTime)->getTimestamp();
        $stopTime    = DateTime::createFromFormat($format, $stopTime)->getTimestamp();
        if ($startTime < $currentTime && $currentTime < $stopTime) {
            return true;
        }
        return false;
    }

    /**
     * @param $date
     * @return string
     */
    protected static function dateConfigure($date): string
    {
        return date_timezone_set($date, timezone_open(self::$timezone))->format(self::$dateFormat);
    }
}
