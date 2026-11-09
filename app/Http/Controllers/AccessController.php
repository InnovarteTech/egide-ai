<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Workspace;
use App\Security\Demo;
use App\Security\Engine;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Inertia\Inertia;

class AccessController extends Controller
{
    public function form(Request $request)
    {
        return Inertia::render('Access', [
            'register' => $request->routeIs('register'),
            'demo' => $this->demoAvailable(),
        ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate(['email' => 'required|email', 'password' => 'required|string|max:200']);
        if (! Auth::attempt($credentials)) {
            return back()->withErrors(['email' => 'Confira o e-mail e a senha.'])->onlyInput('email');
        }
        if ($request->user()->suspended_at) {
            Auth::logout();

            return back()->withErrors(['email' => 'Esta conta está suspensa. Fale com o administrador.'])->onlyInput('email');
        }

        $request->session()->regenerate();

        return redirect()->intended('/');
    }

    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:100', 'email' => 'required|email|max:180|unique:users',
            'password' => 'required|string|min:10|max:128',
        ]);

        $user = DB::transaction(function () use ($data) {
            $user = User::create($data);
            Workspace::create(['user_id' => $user->id, 'name' => $user->name]);

            return $user;
        });
        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/');
    }

    public function demo(Request $request)
    {
        abort_unless($this->demoAvailable(), 404);
        $key = 'demo-account:'.$request->ip();
        if (Demo::accountsFull() || RateLimiter::tooManyAttempts($key, config('egide.demo_accounts_per_ip'))) {
            return back()->withErrors(['email' => 'A demonstração está cheia agora. Tente novamente mais tarde ou crie uma conta.']);
        }
        RateLimiter::hit($key, 86400);

        $user = DB::transaction(function () {
            $user = User::create([
                'name' => 'Visitante da demonstração',
                'email' => 'lab+'.Str::lower(Str::random(16)).'@egide.test',
                'password' => Str::random(36),
            ]);
            Workspace::create(['user_id' => $user->id, 'name' => 'Laboratório Égide AI', 'demo' => true]);

            return $user;
        });
        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/entrar');
    }

    private function demoAvailable(): bool
    {
        return (bool) config('egide.demo_access') && (app()->environment('local') || Engine::platform() !== null);
    }
}
