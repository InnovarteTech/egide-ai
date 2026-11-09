<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('workspaces', function (Blueprint $table): void {
            $table->boolean('demo')->default(false)->index();
        });
    }

    public function down(): void
    {
        Schema::table('workspaces', fn (Blueprint $table) => $table->dropColumn('demo'));
    }
};
