<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use Laravel\Socialite\Facades\Socialite;

Route::middleware('web')->group(function () {
    Route::get('/steam-login', [AuthController::class, 'steam_login']);
    Route::get('/steam-callback', [AuthController::class, 'steam_callback']);
});
// Route::domain('login.skins-hut.com')->group(function () {
// });
