<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table): void {
            $table->string('environment_type', 20)->default('production')->after('write_test');
        });
    }

    public function down(): void
    {
        Schema::table('targets', fn (Blueprint $table) => $table->dropColumn('environment_type'));
    }
};
