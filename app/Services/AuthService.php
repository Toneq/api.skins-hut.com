<?php

namespace App\Services;

use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Payload;
use App\Models\User;
use Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Laravel\Socialite\Facades\Socialite;
use Tymon\JWTAuth\PayloadFactory;

class AuthService
{
    public function steamData($request){
        $userData = $request->all();

        $userData = [
            'steamid' => $request->input('steamid'),
            'personaname' => $request->input('personaname'),
            'profileurl' => $request->input('profileurl'),
            'avatarfull' => $request->input('avatarfull'),
            'avatarhash' => $request->input('avatarhash'),
        ];
        // if (!$token = JWTAuth::attempt($userData)) {
        //     return response()->json(['error' => ['error' => 'Unauthorized']], 401);
        // }
        $payload = JWTAuth::payload()->set('user', $userData);

        $token = JWTAuth::encode($payload);

        return $this->createNewToken($token);
    }

    public function login($request){        
        $validator = Validator::make($request->all(), [
            'token' => 'required|string',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }
    
        try {
            $decodedToken = JWTAuth::setToken($validator->validated()['token'])->getPayload();
            $payloadData = $decodedToken->toArray();

            $user = User::where('steamid', $payloadData['steamid'])->first();

            if ($user) {
                $toUpdate = false;
                if($user->avatar != $payloadData["avatarfull"]){
                    $toUpdate = true;
                    $user->avatar = $payloadData["avatarfull"];
                }
                if($user->username != $payloadData["personaname"]){
                    $toUpdate = true;
                    $user->username = $payloadData["personaname"];
                }
                if($user->avatar_hash != $payloadData["avatarhash"]){
                    $toUpdate = true;
                    $user->avatar_hash = $payloadData["avatarhash"];
                }

                if($toUpdate){
                    $user->save();
                }
            } else {
                $user = new User;
                $user->steamid = $payloadData["steamid"];
                $user->username = $payloadData["personaname"];
                $user->avatar = $payloadData["avatarfull"];
                $user->avatar_hash = $payloadData["avatarhash"];
                $user->save();
            }

            // return response()->json(['success' => true, 'data' => $userData, 'user' => $user]);

            $refreshedToken = JWTAuth::refresh($validator->validated()['token']);
            return $this->createNewToken($refreshedToken);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Token absent'], 401);
        }
    }

    public function register($request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100|unique:users',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors(), 400);
        }
        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));
        return response()->json([
            'message' => 'User successfully registered'
            // 'user' => $user
        ], 201);
    }

    public function logout($request){
        // stare
        // auth()->logout();
        // return response()->json(['message' => 'User successfully signed out']);
        $token = $request->bearerToken(); // Pobierz token z nagłówka Authorization

        if (!$token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }
    
        try {
            JWTAuth::setToken($token)->invalidate();
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Could not invalidate token'], 500);
        }
    
        return response()->json(['message' => 'User successfully signed out']);
    }

    public function refresh(){
        try {
            $token = JWTAuth::parseToken()->refresh();
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token has expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Could not refresh token'], 500);
        }
        return $this->createNewToken($token);
        // return $this->createNewToken(auth()->refresh()); stare
    }

    public function userProfile(){
        // stare
        // return response()->json(auth()->user());

        try {
            $user = JWTAuth::parseToken()->authenticate();

            return response()->json(['user' => $user]);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60
            // 'user' => auth()->user()
        ]);
    }
}
