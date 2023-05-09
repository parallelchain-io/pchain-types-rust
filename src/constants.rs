/*
    Copyright © 2023, ParallelChain Lab 
    Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
*/

//! The protocol defined constants and parameters used across ParallelChain F components.

//////////////////////////////
// Network Account
//////////////////////////////
/// Address of Network Account
pub const NETWORK_ADDRESS: crate::crypto::PublicAddress = [0u8; 32];

//////////////////////////////
// Workload Limits
//////////////////////////////
/// Upper threshold of gas consumption in a block
pub const BLOCK_GAS_LIMIT: u64 = 500_000_000;
/// 1MB
pub const BLOCK_SIZE_LIMIT: usize = 1_048_576;
/// Target Gas Consumption for adjusting network base fee. ref. EIP-1559
pub const TARGET_GAS_CONSUMED: u64 = 250_000_000;
/// MIN_BASE_FEE in units of Grays/Gas
pub const MIN_BASE_FEE: u64 = 8; 

//////////////////////////////
// Economics-related
//////////////////////////////
/// approximately one day
pub const BLOCKS_PER_EPOCH: u64 = 8640;
/// Maximum number of stakes delegated to a pool
pub const MAX_STAKES_PER_POOL: u16 = 128; // = 2^7
/// Maximum number of validators
pub const MAX_VALIDATOR_SET_SIZE: u16 = 64; // = 2^6
/// Send 20% of gas to Treasury
pub const TREASURY_CUT_OF_BASE_FEE: u64 = 20;
/// denominator of Treasury cut of Base fee
pub const TOTAL_BASE_FEE: u64 = 100;
/// Calculate issuance reward at particular epoch:
/// - Issuance_n = (0.0835 * 0.85^(n/365)) / 365 if epoch number < [ISSUANCE_STABLE_EPOCH].
/// - Issuance_n = 0.0150 / 365 otherwise.
/// 
/// Returns the value as tuple of (numerator, denominator)
pub const fn issuance_reward(epoch_number: u64, amount: u64) -> (u128, u128) {
    if epoch_number as usize >= ISSUANCE_STABLE_EPOCH {
        // 15 = 0.015 mutliplied by 1_000
        return ( amount as u128 * 15,  365 * 1_000 );
    } 
    // 835 = 0.0835 mutliplied by 10_000 x value in ISSURANCE_RATE_FACTORS multiplied by 10_000
    let rate = 835 * ISSUANCE_RATE_FACTORS[epoch_number as usize];
    // denominator = 1_000_000
    ( amount as u128 * rate as u128, 365 * 100_000_000 )
}

/// Number of epoch to reach for applying a constant issurance rate in reward calculation
pub const ISSUANCE_STABLE_EPOCH: usize = 3650;
/// 0.85 ^ (n / 365) (and then multply by 10000 to make it integer)
pub const ISSUANCE_RATE_FACTORS: [u64; ISSUANCE_STABLE_EPOCH] = [
    10000,
    9996,
    9991,
    9987,
    9982,
    9978,
    9973,
    9969,
    9964,
    9960,
    9956,
    9951,
    9947,
    9942,
    9938,
    9933,
    9929,
    9925,
    9920,
    9916,
    9911,
    9907,
    9903,
    9898,
    9894,
    9889,
    9885,
    9881,
    9876,
    9872,
    9867,
    9863,
    9859,
    9854,
    9850,
    9845,
    9841,
    9837,
    9832,
    9828,
    9823,
    9819,
    9815,
    9810,
    9806,
    9802,
    9797,
    9793,
    9789,
    9784,
    9780,
    9775,
    9771,
    9767,
    9762,
    9758,
    9754,
    9749,
    9745,
    9741,
    9736,
    9732,
    9728,
    9723,
    9719,
    9715,
    9710,
    9706,
    9702,
    9697,
    9693,
    9689,
    9684,
    9680,
    9676,
    9672,
    9667,
    9663,
    9659,
    9654,
    9650,
    9646,
    9641,
    9637,
    9633,
    9629,
    9624,
    9620,
    9616,
    9611,
    9607,
    9603,
    9599,
    9594,
    9590,
    9586,
    9582,
    9577,
    9573,
    9569,
    9565,
    9560,
    9556,
    9552,
    9547,
    9543,
    9539,
    9535,
    9531,
    9526,
    9522,
    9518,
    9514,
    9509,
    9505,
    9501,
    9497,
    9492,
    9488,
    9484,
    9480,
    9475,
    9471,
    9467,
    9463,
    9459,
    9454,
    9450,
    9446,
    9442,
    9438,
    9433,
    9429,
    9425,
    9421,
    9417,
    9412,
    9408,
    9404,
    9400,
    9396,
    9391,
    9387,
    9383,
    9379,
    9375,
    9371,
    9366,
    9362,
    9358,
    9354,
    9350,
    9346,
    9341,
    9337,
    9333,
    9329,
    9325,
    9321,
    9317,
    9312,
    9308,
    9304,
    9300,
    9296,
    9292,
    9288,
    9283,
    9279,
    9275,
    9271,
    9267,
    9263,
    9259,
    9255,
    9250,
    9246,
    9242,
    9238,
    9234,
    9230,
    9226,
    9222,
    9217,
    9213,
    9209,
    9205,
    9201,
    9197,
    9193,
    9189,
    9185,
    9181,
    9177,
    9172,
    9168,
    9164,
    9160,
    9156,
    9152,
    9148,
    9144,
    9140,
    9136,
    9132,
    9128,
    9124,
    9120,
    9115,
    9111,
    9107,
    9103,
    9099,
    9095,
    9091,
    9087,
    9083,
    9079,
    9075,
    9071,
    9067,
    9063,
    9059,
    9055,
    9051,
    9047,
    9043,
    9039,
    9035,
    9031,
    9027,
    9023,
    9019,
    9015,
    9011,
    9007,
    9003,
    8999,
    8995,
    8991,
    8986,
    8982,
    8978,
    8975,
    8971,
    8967,
    8963,
    8959,
    8955,
    8951,
    8947,
    8943,
    8939,
    8935,
    8931,
    8927,
    8923,
    8919,
    8915,
    8911,
    8907,
    8903,
    8899,
    8895,
    8891,
    8887,
    8883,
    8879,
    8875,
    8871,
    8867,
    8863,
    8859,
    8855,
    8851,
    8848,
    8844,
    8840,
    8836,
    8832,
    8828,
    8824,
    8820,
    8816,
    8812,
    8808,
    8804,
    8800,
    8796,
    8793,
    8789,
    8785,
    8781,
    8777,
    8773,
    8769,
    8765,
    8761,
    8757,
    8753,
    8750,
    8746,
    8742,
    8738,
    8734,
    8730,
    8726,
    8722,
    8718,
    8715,
    8711,
    8707,
    8703,
    8699,
    8695,
    8691,
    8687,
    8684,
    8680,
    8676,
    8672,
    8668,
    8664,
    8660,
    8657,
    8653,
    8649,
    8645,
    8641,
    8637,
    8634,
    8630,
    8626,
    8622,
    8618,
    8614,
    8610,
    8607,
    8603,
    8599,
    8595,
    8591,
    8587,
    8584,
    8580,
    8576,
    8572,
    8568,
    8565,
    8561,
    8557,
    8553,
    8549,
    8546,
    8542,
    8538,
    8534,
    8530,
    8527,
    8523,
    8519,
    8515,
    8511,
    8508,
    8504,
    8500,
    8496,
    8492,
    8489,
    8485,
    8481,
    8477,
    8474,
    8470,
    8466,
    8462,
    8458,
    8455,
    8451,
    8447,
    8443,
    8440,
    8436,
    8432,
    8428,
    8425,
    8421,
    8417,
    8413,
    8410,
    8406,
    8402,
    8398,
    8395,
    8391,
    8387,
    8383,
    8380,
    8376,
    8372,
    8369,
    8365,
    8361,
    8357,
    8354,
    8350,
    8346,
    8343,
    8339,
    8335,
    8331,
    8328,
    8324,
    8320,
    8317,
    8313,
    8309,
    8305,
    8302,
    8298,
    8294,
    8291,
    8287,
    8283,
    8280,
    8276,
    8272,
    8269,
    8265,
    8261,
    8258,
    8254,
    8250,
    8246,
    8243,
    8239,
    8235,
    8232,
    8228,
    8224,
    8221,
    8217,
    8214,
    8210,
    8206,
    8203,
    8199,
    8195,
    8192,
    8188,
    8184,
    8181,
    8177,
    8173,
    8170,
    8166,
    8162,
    8159,
    8155,
    8152,
    8148,
    8144,
    8141,
    8137,
    8133,
    8130,
    8126,
    8123,
    8119,
    8115,
    8112,
    8108,
    8105,
    8101,
    8097,
    8094,
    8090,
    8087,
    8083,
    8079,
    8076,
    8072,
    8069,
    8065,
    8061,
    8058,
    8054,
    8051,
    8047,
    8043,
    8040,
    8036,
    8033,
    8029,
    8026,
    8022,
    8018,
    8015,
    8011,
    8008,
    8004,
    8001,
    7997,
    7993,
    7990,
    7986,
    7983,
    7979,
    7976,
    7972,
    7969,
    7965,
    7961,
    7958,
    7954,
    7951,
    7947,
    7944,
    7940,
    7937,
    7933,
    7930,
    7926,
    7923,
    7919,
    7916,
    7912,
    7908,
    7905,
    7901,
    7898,
    7894,
    7891,
    7887,
    7884,
    7880,
    7877,
    7873,
    7870,
    7866,
    7863,
    7859,
    7856,
    7852,
    7849,
    7845,
    7842,
    7838,
    7835,
    7831,
    7828,
    7824,
    7821,
    7817,
    7814,
    7810,
    7807,
    7804,
    7800,
    7797,
    7793,
    7790,
    7786,
    7783,
    7779,
    7776,
    7772,
    7769,
    7765,
    7762,
    7758,
    7755,
    7752,
    7748,
    7745,
    7741,
    7738,
    7734,
    7731,
    7727,
    7724,
    7721,
    7717,
    7714,
    7710,
    7707,
    7703,
    7700,
    7697,
    7693,
    7690,
    7686,
    7683,
    7679,
    7676,
    7673,
    7669,
    7666,
    7662,
    7659,
    7656,
    7652,
    7649,
    7645,
    7642,
    7639,
    7635,
    7632,
    7628,
    7625,
    7622,
    7618,
    7615,
    7611,
    7608,
    7605,
    7601,
    7598,
    7594,
    7591,
    7588,
    7584,
    7581,
    7578,
    7574,
    7571,
    7567,
    7564,
    7561,
    7557,
    7554,
    7551,
    7547,
    7544,
    7541,
    7537,
    7534,
    7530,
    7527,
    7524,
    7520,
    7517,
    7514,
    7510,
    7507,
    7504,
    7500,
    7497,
    7494,
    7490,
    7487,
    7484,
    7480,
    7477,
    7474,
    7470,
    7467,
    7464,
    7460,
    7457,
    7454,
    7450,
    7447,
    7444,
    7440,
    7437,
    7434,
    7431,
    7427,
    7424,
    7421,
    7417,
    7414,
    7411,
    7407,
    7404,
    7401,
    7398,
    7394,
    7391,
    7388,
    7384,
    7381,
    7378,
    7375,
    7371,
    7368,
    7365,
    7361,
    7358,
    7355,
    7352,
    7348,
    7345,
    7342,
    7338,
    7335,
    7332,
    7329,
    7325,
    7322,
    7319,
    7316,
    7312,
    7309,
    7306,
    7303,
    7299,
    7296,
    7293,
    7290,
    7286,
    7283,
    7280,
    7277,
    7273,
    7270,
    7267,
    7264,
    7260,
    7257,
    7254,
    7251,
    7248,
    7244,
    7241,
    7238,
    7235,
    7231,
    7228,
    7225,
    7222,
    7219,
    7215,
    7212,
    7209,
    7206,
    7203,
    7199,
    7196,
    7193,
    7190,
    7186,
    7183,
    7180,
    7177,
    7174,
    7171,
    7167,
    7164,
    7161,
    7158,
    7155,
    7151,
    7148,
    7145,
    7142,
    7139,
    7135,
    7132,
    7129,
    7126,
    7123,
    7120,
    7116,
    7113,
    7110,
    7107,
    7104,
    7101,
    7097,
    7094,
    7091,
    7088,
    7085,
    7082,
    7079,
    7075,
    7072,
    7069,
    7066,
    7063,
    7060,
    7056,
    7053,
    7050,
    7047,
    7044,
    7041,
    7038,
    7035,
    7031,
    7028,
    7025,
    7022,
    7019,
    7016,
    7013,
    7010,
    7006,
    7003,
    7000,
    6997,
    6994,
    6991,
    6988,
    6985,
    6981,
    6978,
    6975,
    6972,
    6969,
    6966,
    6963,
    6960,
    6957,
    6954,
    6950,
    6947,
    6944,
    6941,
    6938,
    6935,
    6932,
    6929,
    6926,
    6923,
    6920,
    6917,
    6913,
    6910,
    6907,
    6904,
    6901,
    6898,
    6895,
    6892,
    6889,
    6886,
    6883,
    6880,
    6877,
    6874,
    6870,
    6867,
    6864,
    6861,
    6858,
    6855,
    6852,
    6849,
    6846,
    6843,
    6840,
    6837,
    6834,
    6831,
    6828,
    6825,
    6822,
    6819,
    6816,
    6813,
    6810,
    6807,
    6804,
    6800,
    6797,
    6794,
    6791,
    6788,
    6785,
    6782,
    6779,
    6776,
    6773,
    6770,
    6767,
    6764,
    6761,
    6758,
    6755,
    6752,
    6749,
    6746,
    6743,
    6740,
    6737,
    6734,
    6731,
    6728,
    6725,
    6722,
    6719,
    6716,
    6713,
    6710,
    6707,
    6704,
    6701,
    6698,
    6695,
    6692,
    6689,
    6686,
    6683,
    6680,
    6677,
    6674,
    6672,
    6669,
    6666,
    6663,
    6660,
    6657,
    6654,
    6651,
    6648,
    6645,
    6642,
    6639,
    6636,
    6633,
    6630,
    6627,
    6624,
    6621,
    6618,
    6615,
    6612,
    6609,
    6606,
    6604,
    6601,
    6598,
    6595,
    6592,
    6589,
    6586,
    6583,
    6580,
    6577,
    6574,
    6571,
    6568,
    6565,
    6563,
    6560,
    6557,
    6554,
    6551,
    6548,
    6545,
    6542,
    6539,
    6536,
    6533,
    6530,
    6528,
    6525,
    6522,
    6519,
    6516,
    6513,
    6510,
    6507,
    6504,
    6501,
    6499,
    6496,
    6493,
    6490,
    6487,
    6484,
    6481,
    6478,
    6475,
    6473,
    6470,
    6467,
    6464,
    6461,
    6458,
    6455,
    6452,
    6450,
    6447,
    6444,
    6441,
    6438,
    6435,
    6432,
    6429,
    6427,
    6424,
    6421,
    6418,
    6415,
    6412,
    6409,
    6407,
    6404,
    6401,
    6398,
    6395,
    6392,
    6390,
    6387,
    6384,
    6381,
    6378,
    6375,
    6372,
    6370,
    6367,
    6364,
    6361,
    6358,
    6355,
    6353,
    6350,
    6347,
    6344,
    6341,
    6338,
    6336,
    6333,
    6330,
    6327,
    6324,
    6322,
    6319,
    6316,
    6313,
    6310,
    6308,
    6305,
    6302,
    6299,
    6296,
    6294,
    6291,
    6288,
    6285,
    6282,
    6280,
    6277,
    6274,
    6271,
    6268,
    6266,
    6263,
    6260,
    6257,
    6254,
    6252,
    6249,
    6246,
    6243,
    6240,
    6238,
    6235,
    6232,
    6229,
    6227,
    6224,
    6221,
    6218,
    6216,
    6213,
    6210,
    6207,
    6204,
    6202,
    6199,
    6196,
    6193,
    6191,
    6188,
    6185,
    6182,
    6180,
    6177,
    6174,
    6171,
    6169,
    6166,
    6163,
    6160,
    6158,
    6155,
    6152,
    6149,
    6147,
    6144,
    6141,
    6139,
    6136,
    6133,
    6130,
    6128,
    6125,
    6122,
    6119,
    6117,
    6114,
    6111,
    6109,
    6106,
    6103,
    6100,
    6098,
    6095,
    6092,
    6090,
    6087,
    6084,
    6081,
    6079,
    6076,
    6073,
    6071,
    6068,
    6065,
    6062,
    6060,
    6057,
    6054,
    6052,
    6049,
    6046,
    6044,
    6041,
    6038,
    6036,
    6033,
    6030,
    6027,
    6025,
    6022,
    6019,
    6017,
    6014,
    6011,
    6009,
    6006,
    6003,
    6001,
    5998,
    5995,
    5993,
    5990,
    5987,
    5985,
    5982,
    5979,
    5977,
    5974,
    5971,
    5969,
    5966,
    5963,
    5961,
    5958,
    5955,
    5953,
    5950,
    5947,
    5945,
    5942,
    5940,
    5937,
    5934,
    5932,
    5929,
    5926,
    5924,
    5921,
    5918,
    5916,
    5913,
    5911,
    5908,
    5905,
    5903,
    5900,
    5897,
    5895,
    5892,
    5890,
    5887,
    5884,
    5882,
    5879,
    5876,
    5874,
    5871,
    5869,
    5866,
    5863,
    5861,
    5858,
    5856,
    5853,
    5850,
    5848,
    5845,
    5843,
    5840,
    5837,
    5835,
    5832,
    5830,
    5827,
    5824,
    5822,
    5819,
    5817,
    5814,
    5811,
    5809,
    5806,
    5804,
    5801,
    5798,
    5796,
    5793,
    5791,
    5788,
    5786,
    5783,
    5780,
    5778,
    5775,
    5773,
    5770,
    5768,
    5765,
    5762,
    5760,
    5757,
    5755,
    5752,
    5750,
    5747,
    5744,
    5742,
    5739,
    5737,
    5734,
    5732,
    5729,
    5727,
    5724,
    5722,
    5719,
    5716,
    5714,
    5711,
    5709,
    5706,
    5704,
    5701,
    5699,
    5696,
    5694,
    5691,
    5688,
    5686,
    5683,
    5681,
    5678,
    5676,
    5673,
    5671,
    5668,
    5666,
    5663,
    5661,
    5658,
    5656,
    5653,
    5651,
    5648,
    5646,
    5643,
    5641,
    5638,
    5636,
    5633,
    5631,
    5628,
    5626,
    5623,
    5621,
    5618,
    5616,
    5613,
    5611,
    5608,
    5606,
    5603,
    5601,
    5598,
    5596,
    5593,
    5591,
    5588,
    5586,
    5583,
    5581,
    5578,
    5576,
    5573,
    5571,
    5568,
    5566,
    5563,
    5561,
    5558,
    5556,
    5553,
    5551,
    5548,
    5546,
    5543,
    5541,
    5539,
    5536,
    5534,
    5531,
    5529,
    5526,
    5524,
    5521,
    5519,
    5516,
    5514,
    5511,
    5509,
    5507,
    5504,
    5502,
    5499,
    5497,
    5494,
    5492,
    5489,
    5487,
    5485,
    5482,
    5480,
    5477,
    5475,
    5472,
    5470,
    5467,
    5465,
    5463,
    5460,
    5458,
    5455,
    5453,
    5450,
    5448,
    5446,
    5443,
    5441,
    5438,
    5436,
    5433,
    5431,
    5429,
    5426,
    5424,
    5421,
    5419,
    5417,
    5414,
    5412,
    5409,
    5407,
    5405,
    5402,
    5400,
    5397,
    5395,
    5393,
    5390,
    5388,
    5385,
    5383,
    5381,
    5378,
    5376,
    5373,
    5371,
    5369,
    5366,
    5364,
    5361,
    5359,
    5357,
    5354,
    5352,
    5349,
    5347,
    5345,
    5342,
    5340,
    5338,
    5335,
    5333,
    5330,
    5328,
    5326,
    5323,
    5321,
    5319,
    5316,
    5314,
    5312,
    5309,
    5307,
    5304,
    5302,
    5300,
    5297,
    5295,
    5293,
    5290,
    5288,
    5286,
    5283,
    5281,
    5278,
    5276,
    5274,
    5271,
    5269,
    5267,
    5264,
    5262,
    5260,
    5257,
    5255,
    5253,
    5250,
    5248,
    5246,
    5243,
    5241,
    5239,
    5236,
    5234,
    5232,
    5229,
    5227,
    5225,
    5222,
    5220,
    5218,
    5215,
    5213,
    5211,
    5208,
    5206,
    5204,
    5202,
    5199,
    5197,
    5195,
    5192,
    5190,
    5188,
    5185,
    5183,
    5181,
    5178,
    5176,
    5174,
    5171,
    5169,
    5167,
    5165,
    5162,
    5160,
    5158,
    5155,
    5153,
    5151,
    5149,
    5146,
    5144,
    5142,
    5139,
    5137,
    5135,
    5132,
    5130,
    5128,
    5126,
    5123,
    5121,
    5119,
    5117,
    5114,
    5112,
    5110,
    5107,
    5105,
    5103,
    5101,
    5098,
    5096,
    5094,
    5092,
    5089,
    5087,
    5085,
    5082,
    5080,
    5078,
    5076,
    5073,
    5071,
    5069,
    5067,
    5064,
    5062,
    5060,
    5058,
    5055,
    5053,
    5051,
    5049,
    5046,
    5044,
    5042,
    5040,
    5037,
    5035,
    5033,
    5031,
    5028,
    5026,
    5024,
    5022,
    5019,
    5017,
    5015,
    5013,
    5011,
    5008,
    5006,
    5004,
    5002,
    4999,
    4997,
    4995,
    4993,
    4991,
    4988,
    4986,
    4984,
    4982,
    4979,
    4977,
    4975,
    4973,
    4971,
    4968,
    4966,
    4964,
    4962,
    4959,
    4957,
    4955,
    4953,
    4951,
    4948,
    4946,
    4944,
    4942,
    4940,
    4937,
    4935,
    4933,
    4931,
    4929,
    4926,
    4924,
    4922,
    4920,
    4918,
    4916,
    4913,
    4911,
    4909,
    4907,
    4905,
    4902,
    4900,
    4898,
    4896,
    4894,
    4892,
    4889,
    4887,
    4885,
    4883,
    4881,
    4878,
    4876,
    4874,
    4872,
    4870,
    4868,
    4865,
    4863,
    4861,
    4859,
    4857,
    4855,
    4852,
    4850,
    4848,
    4846,
    4844,
    4842,
    4840,
    4837,
    4835,
    4833,
    4831,
    4829,
    4827,
    4824,
    4822,
    4820,
    4818,
    4816,
    4814,
    4812,
    4809,
    4807,
    4805,
    4803,
    4801,
    4799,
    4797,
    4794,
    4792,
    4790,
    4788,
    4786,
    4784,
    4782,
    4780,
    4777,
    4775,
    4773,
    4771,
    4769,
    4767,
    4765,
    4763,
    4760,
    4758,
    4756,
    4754,
    4752,
    4750,
    4748,
    4746,
    4744,
    4741,
    4739,
    4737,
    4735,
    4733,
    4731,
    4729,
    4727,
    4725,
    4722,
    4720,
    4718,
    4716,
    4714,
    4712,
    4710,
    4708,
    4706,
    4704,
    4701,
    4699,
    4697,
    4695,
    4693,
    4691,
    4689,
    4687,
    4685,
    4683,
    4681,
    4678,
    4676,
    4674,
    4672,
    4670,
    4668,
    4666,
    4664,
    4662,
    4660,
    4658,
    4656,
    4654,
    4651,
    4649,
    4647,
    4645,
    4643,
    4641,
    4639,
    4637,
    4635,
    4633,
    4631,
    4629,
    4627,
    4625,
    4623,
    4621,
    4618,
    4616,
    4614,
    4612,
    4610,
    4608,
    4606,
    4604,
    4602,
    4600,
    4598,
    4596,
    4594,
    4592,
    4590,
    4588,
    4586,
    4584,
    4582,
    4580,
    4578,
    4575,
    4573,
    4571,
    4569,
    4567,
    4565,
    4563,
    4561,
    4559,
    4557,
    4555,
    4553,
    4551,
    4549,
    4547,
    4545,
    4543,
    4541,
    4539,
    4537,
    4535,
    4533,
    4531,
    4529,
    4527,
    4525,
    4523,
    4521,
    4519,
    4517,
    4515,
    4513,
    4511,
    4509,
    4507,
    4505,
    4503,
    4501,
    4499,
    4497,
    4495,
    4493,
    4491,
    4489,
    4487,
    4485,
    4483,
    4481,
    4479,
    4477,
    4475,
    4473,
    4471,
    4469,
    4467,
    4465,
    4463,
    4461,
    4459,
    4457,
    4455,
    4453,
    4451,
    4449,
    4447,
    4445,
    4443,
    4441,
    4439,
    4437,
    4435,
    4433,
    4431,
    4429,
    4427,
    4425,
    4423,
    4421,
    4419,
    4417,
    4415,
    4413,
    4411,
    4409,
    4408,
    4406,
    4404,
    4402,
    4400,
    4398,
    4396,
    4394,
    4392,
    4390,
    4388,
    4386,
    4384,
    4382,
    4380,
    4378,
    4376,
    4374,
    4372,
    4370,
    4368,
    4366,
    4365,
    4363,
    4361,
    4359,
    4357,
    4355,
    4353,
    4351,
    4349,
    4347,
    4345,
    4343,
    4341,
    4339,
    4337,
    4336,
    4334,
    4332,
    4330,
    4328,
    4326,
    4324,
    4322,
    4320,
    4318,
    4316,
    4314,
    4312,
    4310,
    4309,
    4307,
    4305,
    4303,
    4301,
    4299,
    4297,
    4295,
    4293,
    4291,
    4289,
    4288,
    4286,
    4284,
    4282,
    4280,
    4278,
    4276,
    4274,
    4272,
    4270,
    4268,
    4267,
    4265,
    4263,
    4261,
    4259,
    4257,
    4255,
    4253,
    4251,
    4249,
    4248,
    4246,
    4244,
    4242,
    4240,
    4238,
    4236,
    4234,
    4233,
    4231,
    4229,
    4227,
    4225,
    4223,
    4221,
    4219,
    4217,
    4216,
    4214,
    4212,
    4210,
    4208,
    4206,
    4204,
    4202,
    4201,
    4199,
    4197,
    4195,
    4193,
    4191,
    4189,
    4188,
    4186,
    4184,
    4182,
    4180,
    4178,
    4176,
    4174,
    4173,
    4171,
    4169,
    4167,
    4165,
    4163,
    4161,
    4160,
    4158,
    4156,
    4154,
    4152,
    4150,
    4149,
    4147,
    4145,
    4143,
    4141,
    4139,
    4137,
    4136,
    4134,
    4132,
    4130,
    4128,
    4126,
    4125,
    4123,
    4121,
    4119,
    4117,
    4115,
    4114,
    4112,
    4110,
    4108,
    4106,
    4104,
    4103,
    4101,
    4099,
    4097,
    4095,
    4093,
    4092,
    4090,
    4088,
    4086,
    4084,
    4083,
    4081,
    4079,
    4077,
    4075,
    4073,
    4072,
    4070,
    4068,
    4066,
    4064,
    4063,
    4061,
    4059,
    4057,
    4055,
    4054,
    4052,
    4050,
    4048,
    4046,
    4045,
    4043,
    4041,
    4039,
    4037,
    4036,
    4034,
    4032,
    4030,
    4028,
    4027,
    4025,
    4023,
    4021,
    4019,
    4018,
    4016,
    4014,
    4012,
    4011,
    4009,
    4007,
    4005,
    4003,
    4002,
    4000,
    3998,
    3996,
    3994,
    3993,
    3991,
    3989,
    3987,
    3986,
    3984,
    3982,
    3980,
    3978,
    3977,
    3975,
    3973,
    3971,
    3970,
    3968,
    3966,
    3964,
    3963,
    3961,
    3959,
    3957,
    3956,
    3954,
    3952,
    3950,
    3948,
    3947,
    3945,
    3943,
    3941,
    3940,
    3938,
    3936,
    3934,
    3933,
    3931,
    3929,
    3927,
    3926,
    3924,
    3922,
    3920,
    3919,
    3917,
    3915,
    3913,
    3912,
    3910,
    3908,
    3907,
    3905,
    3903,
    3901,
    3900,
    3898,
    3896,
    3894,
    3893,
    3891,
    3889,
    3887,
    3886,
    3884,
    3882,
    3881,
    3879,
    3877,
    3875,
    3874,
    3872,
    3870,
    3868,
    3867,
    3865,
    3863,
    3862,
    3860,
    3858,
    3856,
    3855,
    3853,
    3851,
    3850,
    3848,
    3846,
    3844,
    3843,
    3841,
    3839,
    3838,
    3836,
    3834,
    3832,
    3831,
    3829,
    3827,
    3826,
    3824,
    3822,
    3821,
    3819,
    3817,
    3815,
    3814,
    3812,
    3810,
    3809,
    3807,
    3805,
    3804,
    3802,
    3800,
    3798,
    3797,
    3795,
    3793,
    3792,
    3790,
    3788,
    3787,
    3785,
    3783,
    3782,
    3780,
    3778,
    3777,
    3775,
    3773,
    3771,
    3770,
    3768,
    3766,
    3765,
    3763,
    3761,
    3760,
    3758,
    3756,
    3755,
    3753,
    3751,
    3750,
    3748,
    3746,
    3745,
    3743,
    3741,
    3740,
    3738,
    3736,
    3735,
    3733,
    3731,
    3730,
    3728,
    3726,
    3725,
    3723,
    3721,
    3720,
    3718,
    3716,
    3715,
    3713,
    3712,
    3710,
    3708,
    3707,
    3705,
    3703,
    3702,
    3700,
    3698,
    3697,
    3695,
    3693,
    3692,
    3690,
    3688,
    3687,
    3685,
    3684,
    3682,
    3680,
    3679,
    3677,
    3675,
    3674,
    3672,
    3670,
    3669,
    3667,
    3666,
    3664,
    3662,
    3661,
    3659,
    3657,
    3656,
    3654,
    3653,
    3651,
    3649,
    3648,
    3646,
    3644,
    3643,
    3641,
    3640,
    3638,
    3636,
    3635,
    3633,
    3631,
    3630,
    3628,
    3627,
    3625,
    3623,
    3622,
    3620,
    3619,
    3617,
    3615,
    3614,
    3612,
    3610,
    3609,
    3607,
    3606,
    3604,
    3602,
    3601,
    3599,
    3598,
    3596,
    3594,
    3593,
    3591,
    3590,
    3588,
    3586,
    3585,
    3583,
    3582,
    3580,
    3578,
    3577,
    3575,
    3574,
    3572,
    3570,
    3569,
    3567,
    3566,
    3564,
    3563,
    3561,
    3559,
    3558,
    3556,
    3555,
    3553,
    3551,
    3550,
    3548,
    3547,
    3545,
    3544,
    3542,
    3540,
    3539,
    3537,
    3536,
    3534,
    3533,
    3531,
    3529,
    3528,
    3526,
    3525,
    3523,
    3522,
    3520,
    3518,
    3517,
    3515,
    3514,
    3512,
    3511,
    3509,
    3507,
    3506,
    3504,
    3503,
    3501,
    3500,
    3498,
    3497,
    3495,
    3493,
    3492,
    3490,
    3489,
    3487,
    3486,
    3484,
    3483,
    3481,
    3479,
    3478,
    3476,
    3475,
    3473,
    3472,
    3470,
    3469,
    3467,
    3466,
    3464,
    3462,
    3461,
    3459,
    3458,
    3456,
    3455,
    3453,
    3452,
    3450,
    3449,
    3447,
    3446,
    3444,
    3442,
    3441,
    3439,
    3438,
    3436,
    3435,
    3433,
    3432,
    3430,
    3429,
    3427,
    3426,
    3424,
    3423,
    3421,
    3420,
    3418,
    3417,
    3415,
    3413,
    3412,
    3410,
    3409,
    3407,
    3406,
    3404,
    3403,
    3401,
    3400,
    3398,
    3397,
    3395,
    3394,
    3392,
    3391,
    3389,
    3388,
    3386,
    3385,
    3383,
    3382,
    3380,
    3379,
    3377,
    3376,
    3374,
    3373,
    3371,
    3370,
    3368,
    3367,
    3365,
    3364,
    3362,
    3361,
    3359,
    3358,
    3356,
    3355,
    3353,
    3352,
    3350,
    3349,
    3347,
    3346,
    3344,
    3343,
    3341,
    3340,
    3338,
    3337,
    3335,
    3334,
    3332,
    3331,
    3329,
    3328,
    3326,
    3325,
    3323,
    3322,
    3321,
    3319,
    3318,
    3316,
    3315,
    3313,
    3312,
    3310,
    3309,
    3307,
    3306,
    3304,
    3303,
    3301,
    3300,
    3298,
    3297,
    3296,
    3294,
    3293,
    3291,
    3290,
    3288,
    3287,
    3285,
    3284,
    3282,
    3281,
    3279,
    3278,
    3276,
    3275,
    3274,
    3272,
    3271,
    3269,
    3268,
    3266,
    3265,
    3263,
    3262,
    3260,
    3259,
    3258,
    3256,
    3255,
    3253,
    3252,
    3250,
    3249,
    3247,
    3246,
    3245,
    3243,
    3242,
    3240,
    3239,
    3237,
    3236,
    3234,
    3233,
    3232,
    3230,
    3229,
    3227,
    3226,
    3224,
    3223,
    3222,
    3220,
    3219,
    3217,
    3216,
    3214,
    3213,
    3211,
    3210,
    3209,
    3207,
    3206,
    3204,
    3203,
    3201,
    3200,
    3199,
    3197,
    3196,
    3194,
    3193,
    3192,
    3190,
    3189,
    3187,
    3186,
    3184,
    3183,
    3182,
    3180,
    3179,
    3177,
    3176,
    3175,
    3173,
    3172,
    3170,
    3169,
    3167,
    3166,
    3165,
    3163,
    3162,
    3160,
    3159,
    3158,
    3156,
    3155,
    3153,
    3152,
    3151,
    3149,
    3148,
    3146,
    3145,
    3144,
    3142,
    3141,
    3139,
    3138,
    3137,
    3135,
    3134,
    3132,
    3131,
    3130,
    3128,
    3127,
    3125,
    3124,
    3123,
    3121,
    3120,
    3118,
    3117,
    3116,
    3114,
    3113,
    3112,
    3110,
    3109,
    3107,
    3106,
    3105,
    3103,
    3102,
    3100,
    3099,
    3098,
    3096,
    3095,
    3094,
    3092,
    3091,
    3089,
    3088,
    3087,
    3085,
    3084,
    3083,
    3081,
    3080,
    3078,
    3077,
    3076,
    3074,
    3073,
    3072,
    3070,
    3069,
    3068,
    3066,
    3065,
    3063,
    3062,
    3061,
    3059,
    3058,
    3057,
    3055,
    3054,
    3053,
    3051,
    3050,
    3048,
    3047,
    3046,
    3044,
    3043,
    3042,
    3040,
    3039,
    3038,
    3036,
    3035,
    3034,
    3032,
    3031,
    3030,
    3028,
    3027,
    3025,
    3024,
    3023,
    3021,
    3020,
    3019,
    3017,
    3016,
    3015,
    3013,
    3012,
    3011,
    3009,
    3008,
    3007,
    3005,
    3004,
    3003,
    3001,
    3000,
    2999,
    2997,
    2996,
    2995,
    2993,
    2992,
    2991,
    2989,
    2988,
    2987,
    2985,
    2984,
    2983,
    2981,
    2980,
    2979,
    2977,
    2976,
    2975,
    2973,
    2972,
    2971,
    2969,
    2968,
    2967,
    2965,
    2964,
    2963,
    2962,
    2960,
    2959,
    2958,
    2956,
    2955,
    2954,
    2952,
    2951,
    2950,
    2948,
    2947,
    2946,
    2944,
    2943,
    2942,
    2940,
    2939,
    2938,
    2937,
    2935,
    2934,
    2933,
    2931,
    2930,
    2929,
    2927,
    2926,
    2925,
    2924,
    2922,
    2921,
    2920,
    2918,
    2917,
    2916,
    2914,
    2913,
    2912,
    2911,
    2909,
    2908,
    2907,
    2905,
    2904,
    2903,
    2901,
    2900,
    2899,
    2898,
    2896,
    2895,
    2894,
    2892,
    2891,
    2890,
    2889,
    2887,
    2886,
    2885,
    2883,
    2882,
    2881,
    2880,
    2878,
    2877,
    2876,
    2874,
    2873,
    2872,
    2871,
    2869,
    2868,
    2867,
    2866,
    2864,
    2863,
    2862,
    2860,
    2859,
    2858,
    2857,
    2855,
    2854,
    2853,
    2852,
    2850,
    2849,
    2848,
    2846,
    2845,
    2844,
    2843,
    2841,
    2840,
    2839,
    2838,
    2836,
    2835,
    2834,
    2833,
    2831,
    2830,
    2829,
    2827,
    2826,
    2825,
    2824,
    2822,
    2821,
    2820,
    2819,
    2817,
    2816,
    2815,
    2814,
    2812,
    2811,
    2810,
    2809,
    2807,
    2806,
    2805,
    2804,
    2802,
    2801,
    2800,
    2799,
    2797,
    2796,
    2795,
    2794,
    2792,
    2791,
    2790,
    2789,
    2787,
    2786,
    2785,
    2784,
    2783,
    2781,
    2780,
    2779,
    2778,
    2776,
    2775,
    2774,
    2773,
    2771,
    2770,
    2769,
    2768,
    2766,
    2765,
    2764,
    2763,
    2762,
    2760,
    2759,
    2758,
    2757,
    2755,
    2754,
    2753,
    2752,
    2751,
    2749,
    2748,
    2747,
    2746,
    2744,
    2743,
    2742,
    2741,
    2740,
    2738,
    2737,
    2736,
    2735,
    2733,
    2732,
    2731,
    2730,
    2729,
    2727,
    2726,
    2725,
    2724,
    2722,
    2721,
    2720,
    2719,
    2718,
    2716,
    2715,
    2714,
    2713,
    2712,
    2710,
    2709,
    2708,
    2707,
    2706,
    2704,
    2703,
    2702,
    2701,
    2700,
    2698,
    2697,
    2696,
    2695,
    2694,
    2692,
    2691,
    2690,
    2689,
    2688,
    2686,
    2685,
    2684,
    2683,
    2682,
    2680,
    2679,
    2678,
    2677,
    2676,
    2674,
    2673,
    2672,
    2671,
    2670,
    2668,
    2667,
    2666,
    2665,
    2664,
    2663,
    2661,
    2660,
    2659,
    2658,
    2657,
    2655,
    2654,
    2653,
    2652,
    2651,
    2650,
    2648,
    2647,
    2646,
    2645,
    2644,
    2642,
    2641,
    2640,
    2639,
    2638,
    2637,
    2635,
    2634,
    2633,
    2632,
    2631,
    2630,
    2628,
    2627,
    2626,
    2625,
    2624,
    2623,
    2621,
    2620,
    2619,
    2618,
    2617,
    2616,
    2614,
    2613,
    2612,
    2611,
    2610,
    2609,
    2607,
    2606,
    2605,
    2604,
    2603,
    2602,
    2600,
    2599,
    2598,
    2597,
    2596,
    2595,
    2594,
    2592,
    2591,
    2590,
    2589,
    2588,
    2587,
    2585,
    2584,
    2583,
    2582,
    2581,
    2580,
    2579,
    2577,
    2576,
    2575,
    2574,
    2573,
    2572,
    2571,
    2569,
    2568,
    2567,
    2566,
    2565,
    2564,
    2563,
    2561,
    2560,
    2559,
    2558,
    2557,
    2556,
    2555,
    2553,
    2552,
    2551,
    2550,
    2549,
    2548,
    2547,
    2545,
    2544,
    2543,
    2542,
    2541,
    2540,
    2539,
    2538,
    2536,
    2535,
    2534,
    2533,
    2532,
    2531,
    2530,
    2529,
    2527,
    2526,
    2525,
    2524,
    2523,
    2522,
    2521,
    2520,
    2518,
    2517,
    2516,
    2515,
    2514,
    2513,
    2512,
    2511,
    2509,
    2508,
    2507,
    2506,
    2505,
    2504,
    2503,
    2502,
    2501,
    2499,
    2498,
    2497,
    2496,
    2495,
    2494,
    2493,
    2492,
    2491,
    2489,
    2488,
    2487,
    2486,
    2485,
    2484,
    2483,
    2482,
    2481,
    2479,
    2478,
    2477,
    2476,
    2475,
    2474,
    2473,
    2472,
    2471,
    2470,
    2468,
    2467,
    2466,
    2465,
    2464,
    2463,
    2462,
    2461,
    2460,
    2459,
    2457,
    2456,
    2455,
    2454,
    2453,
    2452,
    2451,
    2450,
    2449,
    2448,
    2447,
    2445,
    2444,
    2443,
    2442,
    2441,
    2440,
    2439,
    2438,
    2437,
    2436,
    2435,
    2434,
    2432,
    2431,
    2430,
    2429,
    2428,
    2427,
    2426,
    2425,
    2424,
    2423,
    2422,
    2421,
    2419,
    2418,
    2417,
    2416,
    2415,
    2414,
    2413,
    2412,
    2411,
    2410,
    2409,
    2408,
    2407,
    2406,
    2404,
    2403,
    2402,
    2401,
    2400,
    2399,
    2398,
    2397,
    2396,
    2395,
    2394,
    2393,
    2392,
    2391,
    2389,
    2388,
    2387,
    2386,
    2385,
    2384,
    2383,
    2382,
    2381,
    2380,
    2379,
    2378,
    2377,
    2376,
    2375,
    2374,
    2373,
    2371,
    2370,
    2369,
    2368,
    2367,
    2366,
    2365,
    2364,
    2363,
    2362,
    2361,
    2360,
    2359,
    2358,
    2357,
    2356,
    2355,
    2354,
    2353,
    2352,
    2350,
    2349,
    2348,
    2347,
    2346,
    2345,
    2344,
    2343,
    2342,
    2341,
    2340,
    2339,
    2338,
    2337,
    2336,
    2335,
    2334,
    2333,
    2332,
    2331,
    2330,
    2329,
    2328,
    2327,
    2325,
    2324,
    2323,
    2322,
    2321,
    2320,
    2319,
    2318,
    2317,
    2316,
    2315,
    2314,
    2313,
    2312,
    2311,
    2310,
    2309,
    2308,
    2307,
    2306,
    2305,
    2304,
    2303,
    2302,
    2301,
    2300,
    2299,
    2298,
    2297,
    2296,
    2295,
    2294,
    2293,
    2292,
    2291,
    2290,
    2288,
    2287,
    2286,
    2285,
    2284,
    2283,
    2282,
    2281,
    2280,
    2279,
    2278,
    2277,
    2276,
    2275,
    2274,
    2273,
    2272,
    2271,
    2270,
    2269,
    2268,
    2267,
    2266,
    2265,
    2264,
    2263,
    2262,
    2261,
    2260,
    2259,
    2258,
    2257,
    2256,
    2255,
    2254,
    2253,
    2252,
    2251,
    2250,
    2249,
    2248,
    2247,
    2246,
    2245,
    2244,
    2243,
    2242,
    2241,
    2240,
    2239,
    2238,
    2237,
    2236,
    2235,
    2234,
    2233,
    2232,
    2231,
    2230,
    2229,
    2228,
    2227,
    2226,
    2225,
    2224,
    2223,
    2222,
    2221,
    2220,
    2219,
    2218,
    2217,
    2216,
    2215,
    2214,
    2213,
    2212,
    2211,
    2210,
    2209,
    2208,
    2207,
    2206,
    2205,
    2204,
    2203,
    2203,
    2202,
    2201,
    2200,
    2199,
    2198,
    2197,
    2196,
    2195,
    2194,
    2193,
    2192,
    2191,
    2190,
    2189,
    2188,
    2187,
    2186,
    2185,
    2184,
    2183,
    2182,
    2181,
    2180,
    2179,
    2178,
    2177,
    2176,
    2175,
    2174,
    2173,
    2172,
    2171,
    2170,
    2169,
    2168,
    2167,
    2167,
    2166,
    2165,
    2164,
    2163,
    2162,
    2161,
    2160,
    2159,
    2158,
    2157,
    2156,
    2155,
    2154,
    2153,
    2152,
    2151,
    2150,
    2149,
    2148,
    2147,
    2146,
    2145,
    2144,
    2143,
    2143,
    2142,
    2141,
    2140,
    2139,
    2138,
    2137,
    2136,
    2135,
    2134,
    2133,
    2132,
    2131,
    2130,
    2129,
    2128,
    2127,
    2126,
    2125,
    2124,
    2124,
    2123,
    2122,
    2121,
    2120,
    2119,
    2118,
    2117,
    2116,
    2115,
    2114,
    2113,
    2112,
    2111,
    2110,
    2109,
    2108,
    2108,
    2107,
    2106,
    2105,
    2104,
    2103,
    2102,
    2101,
    2100,
    2099,
    2098,
    2097,
    2096,
    2095,
    2094,
    2094,
    2093,
    2092,
    2091,
    2090,
    2089,
    2088,
    2087,
    2086,
    2085,
    2084,
    2083,
    2082,
    2081,
    2080,
    2080,
    2079,
    2078,
    2077,
    2076,
    2075,
    2074,
    2073,
    2072,
    2071,
    2070,
    2069,
    2068,
    2068,
    2067,
    2066,
    2065,
    2064,
    2063,
    2062,
    2061,
    2060,
    2059,
    2058,
    2057,
    2057,
    2056,
    2055,
    2054,
    2053,
    2052,
    2051,
    2050,
    2049,
    2048,
    2047,
    2047,
    2046,
    2045,
    2044,
    2043,
    2042,
    2041,
    2040,
    2039,
    2038,
    2037,
    2037,
    2036,
    2035,
    2034,
    2033,
    2032,
    2031,
    2030,
    2029,
    2028,
    2027,
    2027,
    2026,
    2025,
    2024,
    2023,
    2022,
    2021,
    2020,
    2019,
    2018,
    2018,
    2017,
    2016,
    2015,
    2014,
    2013,
    2012,
    2011,
    2010,
    2009,
    2009,
    2008,
    2007,
    2006,
    2005,
    2004,
    2003,
    2002,
    2001,
    2001,
    2000,
    1999,
    1998,
    1997,
    1996,
    1995,
    1994,
    1993,
    1993,
    1992,
    1991,
    1990,
    1989,
    1988,
    1987,
    1986,
    1985,
    1985,
    1984,
    1983,
    1982,
    1981,
    1980,
    1979,
    1978,
    1978,
    1977,
    1976,
    1975,
    1974,
    1973,
    1972,
    1971,
    1970,
    1970,
];