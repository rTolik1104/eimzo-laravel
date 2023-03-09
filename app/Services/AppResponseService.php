<?php

namespace App\Services;

/**
 * Class ErgReturnResponseService
 * @author Alexandr Hackimov https://github.com/hackimov
 *
 */

use Illuminate\Http\JsonResponse;

class AppResponseService
{
    public static function error($message, $appCode, $httpCode, $data = null): JsonResponse
    {
        if(isset(AppTranslations::$translations[$appCode])){
            $message = [
                'en' => $message,
                'ru' => AppTranslations::$translations[$appCode]
            ];
        }

        return response()->json([
            'message' => $message,
            'data'    => $data,
            'code'    => $appCode,
            'success' => false
        ], $httpCode);
    }

    public static function success($message, $data = null): JsonResponse
    {
        return response()->json([
            'message' => $message,
            'data'    => $data,
            'code'    => 0,
            'success' => true
        ]);
    }

    public static function arrayError($message, $appCode, $data = null): array
    {
        return [
            'message' => $message,
            'data'    => $data,
            'code'    => $appCode,
            'success' => false,
        ];
    }

    public static function arraySuccess($message, $data = null): array
    {
        return [
            'message' => $message,
            'data'    => $data,
            'code'    => 0,
            'success' => true
        ];
    }
}
