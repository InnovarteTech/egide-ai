<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table): void {
            $table->boolean('write_test')->default(false)->after('api_origin');
        });
    }

    public function down(): void
    {
        Schema::table('targets', fn (Blueprint $table) => $table->dropColumn('write_test'));
    }
};
