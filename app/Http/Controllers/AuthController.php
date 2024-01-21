<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Services\AuthService;

class AuthController extends Controller
{
    protected $authService;

    public function __construct(AuthService $authService){
        $this->middleware(['web', 'auth:api'], ['except' => ['login', 'steam_login', 'steam_callback']]);
        $this->authService = $authService;
    }

    public function login(Request $request){
        return $this->authService->login($request);
    }

    public function logout(Request $request){
        return $this->authService->logout($request);
    }

    public function refresh(){
        return $this->authService->refresh();
    }

    public function user_profile(Request $request){
        return $this->authService->userProfile($request);
    }

    public function steam_data(Request $request){
        return $this->authService->steamData($request);
    }
}
