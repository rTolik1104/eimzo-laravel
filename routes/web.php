<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::group(['prefix' => '/api/gnk', 'namespace' => '\App\Http\Controllers\gnk'], static function () {
    # eimzo handle
    Route::post('eimzo/upload','GnkEimzoController@handleRequest');
    # check signature by document_id
    Route::post('eimzo/check_document_id','GnkEimzoController@checkDocumentId');
});
