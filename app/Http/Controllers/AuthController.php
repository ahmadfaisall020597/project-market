<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    //
    public function register(Request $request)
    {
        // Validasi input dari request

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'otp' => Str::random(6),
        ]);

        $this->sendOtpEmail($user);

        return response()->json(['message' => 'Registration successful. OTP sent to your email.']);
    }

    public function login(Request $request)
    {
        // Validasi input dari request

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Invalid email or password.'], 401);
        }

        $otp = Str::random(6);
        $user->otp = $otp;
        $user->save();

        $this->sendOtpEmail($user);

        return response()->json(['message' => 'Login successful. OTP sent to your email.']);
    }

    protected function sendOtpEmail($user)
    {
        $otp = $user->otp;

        Mail::raw("Your OTP is: $otp", function ($message) use ($user) {
            $message->to($user->email)
                ->subject('OTP for Authentication');
        });
    }

    public function verifyOtp(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user || $user->otp !== $request->otp) {
            // Tambahkan output debug atau log
            Log::error("Invalid OTP - User: " . ($user ? $user->id : 'null') . ", Entered OTP: " . $request->otp);

            return response()->json(['error' => 'Invalid OTP.'], 401);
        }

        $token = $user->createToken('otp-token')->plainTextToken;

        // Clear OTP setelah verifikasi
        $user->otp = null;
        $user->save();

        return response()->json(['token' => $token, 'message' => 'OTP verified.']);
    }
}
