<?php

namespace App\Models\Gnk;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class EimzoAppSignature extends Model
{
    protected $primaryKey = 'eimzo_app_signature_id';

    public $timestamps = false;

    protected $fillable = [
        'document_id',
        'signature_data',
        'signature_pkcs7',
        'signature_key_id',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'eimzo_app_signature_id' => 'string'
    ];
}
