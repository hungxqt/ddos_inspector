#include <gtest/gtest.h>
#include "../src/stats_engine.cpp"

TEST(EWMATest, SpikeDetection) {
    // Insert simple test to validate spike detection
    EXPECT_TRUE(detectSpike(/* test values */));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
