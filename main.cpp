#include "pch.h"
#include "Bot/GameBot.h"

void PrintBanner() {
    std::cout << "\n";
    std::cout << "  _____             _      _______              _    _             _    \n";
    std::cout << " |  __ \\           | |    |  ___  |            | |  | |           | |   \n";
    std::cout << " | |  | | __ _ _ __| | __ | |   | | __ _  ___  | |__| | ___   ___ | | __\n";
    std::cout << " | |  | |/ _` | '__| |/ / | |___| |/ _` |/ _ \\ |  __  |/ _ \\ / _ \\| |/ /\n";
    std::cout << " | |__| | (_| | |  |   <  |  ___  | (_| |  __/ | |  | | (_) | (_) |   < \n";
    std::cout << " |_____/ \\__,_|_|  |_|\\_\\ |_|   |_|\\__, |\\___| |_|  |_|\\___/ \\___/|_|\\_\\\n";
    std::cout << "                                    __/ |                               \n";
    std::cout << "                                   |___/                                \n";
    std::cout << "  [ Dark Ages Game Bot ]\n\n";
}

int main() {
    PrintBanner();
    DarkAges::Bot::GameBot bot;
    if (!bot.Initialize()) return 1;
    bot.PrintMenu();
    while (bot.IsRunning()) bot.Update();
    bot.Shutdown();
    std::cout << "\n[SYSTEM] Shutdown complete.\n";
    return 0;
}