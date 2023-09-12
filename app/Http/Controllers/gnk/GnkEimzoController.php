<?php

namespace App\Http\Controllers\gnk;

use App\Http\Controllers\Controller;
use App\Http\Controllers\eimzo\HackimovSignParser;
use App\Models\Gnk\EimzoAppSignature;
use App\Services\AppResponseService;
use Illuminate\Http\JsonResponse;

class GnkEimzoController extends Controller
{
    /**
     * Если пользователь подписывает документ с помощью ID-карты E-imo, GNK отправляет данные подписи этому методу.
     * Этот метод сохраняет информацию и возвращает ответ GNK.
     * @return JsonResponse
     */
    public function handleRequest()
    {
        if(!isset(request()->pkcs7_b64) || !isset(request()->document_id) || !isset(request()->serial_number)){
            return response()->json([
                'success' => false,
                'message' => 'Page not found'
            ]);
        }

        $isSignature = HackimovSignParser::isSignature(request()->pkcs7_b64);
        $signature = HackimovSignParser::signParse(request()->pkcs7_b64);

        if(!$isSignature || !$signature){
            return response()->json([
                'success' => false,
                'message' => 'Wrong signature'
            ]);
        }
        $eimzoAppSignature = EimzoAppSignature::where('signature_key_id',$signature[0]['key_id'])->first();
        $eimzoAppSignatureParams = [
            'signature_key_id' => $signature[0]['key_id'],
            'document_id'     => request()->document_id,
            'signature_data'  => json_encode($signature[0]),
            'signature_pkcs7' => request()->pkcs7_b64,
        ];
        if($eimzoAppSignature){
            $eimzoAppSignature->update($eimzoAppSignatureParams);
        }else{
            EimzoAppSignature::create($eimzoAppSignatureParams);
        }

        return response()->json([
            'success' => true,
            'message' => 'Successfully signed',
        ]);
    }

    /**
     * Этот метод проверяет подпись по document_id
     * Если в БД есть document_id, возвращает document_id и sinature_pkcs7
     * @return JsonResponse
     */
    public function checkDocumentId()
    {
        if(!isset(request()->document_id)){
            return AppResponseService::error('Page not found',3119,404);
        }
        $signature = EimzoAppSignature::where('document_id',request()->document_id)->first();
        if($signature != null){
            return AppResponseService::success('success', [
                'document_id' => $signature->document_id ?? '',
                'signature_pkcs7' => $signature->signature_pkcs7 ?? '',
                'signature_data' => json_decode($signature->signature_data ?? [],true)
            ]);
        }
        return AppResponseService::error('Document id not found',0,404);
    }

    public function getSignList()
    {
        if(!isset(request()->document_id)){
            return AppResponseService::error('Page not found',3119,404);
        }

        $signatures = EimzoAppSignature::where('document_id',request()->document_id);

        $data = array();
        if($signatures != null){
            foreach ($signatures as $signature)
            {
                $signData = [
                    'document_id' => $signature->document_id ?? '',
                    'signature_pkcs7' => $signature->signature_pkcs7 ?? '',
                    'signature_data' => json_decode($signature->signature_data ?? [],true)
                ];

                $data[] = $signData;
            }

            $out = array_values($data);
            return AppResponseService::success('success', json_encode($data));
        }
        return AppResponseService::error('Document id not found',0,404);
    }
}
