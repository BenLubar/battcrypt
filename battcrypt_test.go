package battcrypt

import (
	"encoding/hex"
	"testing"
)

func TestHashes(t *testing.T) {
	// converted from https://github.com/bsdphk/PHC/blob/master/Battcrypt/test_vectors/test_vectors.txt
	var table = []struct {
		Password, Salt, Hash string
		Time, Upgrade, Mem   uint64
	}{
		{Password: "70617373776f7264", Salt: "73616c74", Time: 0, Upgrade: 0, Mem: 0, Hash: "e22441865a5405c2bbe84a4d6e025133595042886125989fafcf409493638d660803f13cc0fff9e902b3a017cb5b7bceb52ac404be77828dac531f01a25d17da"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 1, Upgrade: 0, Mem: 0, Hash: "a6ddd44ec442a4efa2b040ecdfe55faba23a868b62f975bab4231ab6055e4012b6a067bab54da6473514d662f3323a22778570a0a7734ac151dd4d1f80c39bbb"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 0, Upgrade: 0, Mem: 1, Hash: "c1ac3c9cc59f300122a8bc423fd75bde203f67a5ed6d318edfb4f8ab9c193d55ae6efa907dcc73838452c85adf393e9687f80a67d8ef199ec1b8b6b1513744c0"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 1, Upgrade: 0, Mem: 1, Hash: "fd23460ecf2280bdf10405f025ec98a3ac393375a8ba6c62105cf8c90e19f2b37e479a5871fe1049301462359d3334acb67a3cef51fb087312fbe58787ae5e0b"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 1, Upgrade: 1, Mem: 1, Hash: "20fd1723be1221f22877d40ba73b30130d1594480d0e014b381a1007b776a30939389c2b11e060138aa1c8283c9519cd33374827aaf6f2b4de7d10e74da39695"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 2, Upgrade: 2, Mem: 2, Hash: "236bd31ab673511bc2fa5ed6125b8f8a2f09e3ddeb2f0db98096de2288061d03872536958325bd41a378e574f3bfcad4d71b9f32844da152728afdb543ad952c"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 3, Upgrade: 3, Mem: 3, Hash: "52952e1f2065de4ac1efbccdb99f0a059c8d707a8bc419ff5fc9ec88a47225738df815c7e0265970e0b66fb444e1124a8c1f2fda68eeb6c11cb49c2baf3eb19b"},
		{Password: "70617373776f7264", Salt: "73616c74", Time: 4, Upgrade: 4, Mem: 4, Hash: "6e761e1b895e0b397bfe766eacf55768394898583c6c661b3ed534309f038d9c3212a1a97c45d2e09b9a841807762e7f8f01dd3696a2378f4c792cd3ca132dc8"},
		{Password: "ff00", Salt: "80", Time: 0, Upgrade: 0, Mem: 0, Hash: "3ecb2d9c9d26a6af3ec26aa01452b548dea6bb4c23ff77f250413a23fc2b97ba0e2aedbfe1a37ba869c76c841e0b8b48f77722e188bcd79ebf4bbbfb277322de"},
		{Password: "ff00", Salt: "80", Time: 1, Upgrade: 1, Mem: 1, Hash: "2ec48d96674917b58cfac021c049d7308e626ebc702e7f507ee9262479f2b204b823611f24ffb4ea719ef2fd164346b94ed03b614df7458ebbef5c69d5e201e7"},
		{Password: "ff00", Salt: "80", Time: 2, Upgrade: 2, Mem: 2, Hash: "ec774564745802ce11f17c9d310093758e6b5a73c067a8b7e1b74f12d1ecc079929cf6c620ffaaef01fca8c03009c83bed2cf5a979ad54bb2f6fb336e5833d6a"},
		{Password: "ff00", Salt: "80", Time: 3, Upgrade: 3, Mem: 3, Hash: "9a5fcc8ccd16137a307e4a7e2a01272e3a6c755a186a7e608d62466afecfd1abf561d13596349dd1b9eabd73aeedbfdac3bc75dbf9b3db42d70ecf73e97a0b42"},
		{Password: "", Salt: "", Time: 2, Upgrade: 0, Mem: 2, Hash: "54dec681881ba1381dc1617220be34317adc6c0ce6771c1c655a6eb901392ce8cfff6a426ea04b5fffb3ddb0ab6b634bb8e9ca3654eb5c14a6dc8475ce56e353"},
		{Password: "00", Salt: "00", Time: 2, Upgrade: 0, Mem: 2, Hash: "eb70097b72daf153e950b3192068427362252b86ff092aa6b00d52d387f6757769e4a6d2bd4573f28b23e3997fb68f389c382ee2c62850ad6dae4bc680383988"},
		{Password: "0001", Salt: "0100", Time: 2, Upgrade: 0, Mem: 2, Hash: "4c8b30eafb728b337ceab4cbd2d65f8427200d07f2f8461e057f4532124a8dfacabd2e51c80d21b50acd10a1586c5fcf86b691a05428220d144211a1f843782a"},
		{Password: "000102", Salt: "020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "234410e2d0e55316f1e93bbbaf93a731b246291f7b1f9f01c25ad22d4f9dd9964174d4fb3efd3dff3a934c3dca439e99aff5e3a3661db497e33bdecd549dfa77"},
		{Password: "00010203", Salt: "03020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "c54ad8e4784d9b7c021f0bbadd7413efd9c6863a88e3614b6a2f8e8b05bb13230eced4b50cbcea8e5632dd247a1a3e40118e2d842f8290720831b5c965b9cdb9"},
		{Password: "0001020304", Salt: "0403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "48c12352fce9ca03da83a1460fbab5bb486fc82888f78fc38b972f56080a3d4587d12015b34b4894c4bf533ee0db83fd744ec99034e5338e0f0b6a48a91282cb"},
		{Password: "000102030405", Salt: "050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "e447c752478d114abbcfa1aa3058f215b59e33dc8066ba5d69175cf7927894791782d07ace9af736453ff6e9ff89c0d37664bf6c555a189b1e72d82d7901efbb"},
		{Password: "00010203040506", Salt: "06050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "6928e8e9cb98f1552d9d8c3bbabc9d28a2a9dc3eacf6e17562b693fc6d6d40ad10ce3a53c1720c6d07e73dbf958c4cfbd2993cc195f8026ef44b30c4e9e47678"},
		{Password: "0001020304050607", Salt: "0706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "0c93eacf153d51b08b66cc6eea390a61f284ffd2033de406d098e628e0fb51f4a4ac1178f2fa5d1954f4ba97c22fbd1e9345e64ef80650a3dcdf04cd773f41ae"},
		{Password: "000102030405060708", Salt: "080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "ada2f0f14b03e0a23fb5a21aa91f3a5d7897ab540b4144f6a7e6422c7a45302e9429aa5ebaacbfe26d6bbdd19e1700a93ea82299a2c56636f6e9dedd3371427f"},
		{Password: "00010203040506070809", Salt: "09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "76aa97e669cde936ef4ab693c0256d8b33f37caf0ad41c4f4ecd8c6bc96c02fe8435867460fffc9d3280791c10121945c7396cdeb7b5459985ad715178857d93"},
		{Password: "000102030405060708090a", Salt: "0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "8e38d3bce4b748bf094468d2c1c59dafdf8e1536bff431736a91a8702528cb1aa1ca2d34b101d97abc66081bc0c8c03ea947b624df2bc0aaaedfc9ec9d56cd3b"},
		{Password: "000102030405060708090a0b", Salt: "0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "262f76fd5385e939720f0afc755f2193b89925c6964250df307cd7cf40c163dc27acddf677c4b2a4d3f6f1d3ca5d1b4acf6c88681966c37756f2b18fb5c5d196"},
		{Password: "000102030405060708090a0b0c", Salt: "0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "e20d737454309249cff6f840212fc6c3d13cd0431d1fcc2dd8ab144fbd8fc96567de1e928e5dc0d0baef8b93ef9b0f484f8327d9338ac1a54b0daca5699a7a7f"},
		{Password: "000102030405060708090a0b0c0d", Salt: "0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "b74401d6795409658f2754413f79143e948fa15ae2f83c448ad85d22ebf4b1fbe43c77a768fe27bdae58e8a13d3bf1eab12ded54e9f5ed46e166336626d83eb2"},
		{Password: "000102030405060708090a0b0c0d0e", Salt: "0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "4c2734c6b893ed09e17dd6c3d59298089d0470d8355e0af23f5601a25f450561200f788abf4e4df9ce5142b26e83592ab48cee23817c772ad96e20c461a2114d"},
		{Password: "000102030405060708090a0b0c0d0e0f", Salt: "0f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "491711165489d80012ff102a603091ea65424e85d97fb089934f21fc847984cd1f32ef4eadb2f83187f81a6c140635f5bdbad53847e5e221eab24f2e3cdc948b"},
		{Password: "000102030405060708090a0b0c0d0e0f10", Salt: "100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "8e636da152e3c7596b2f24afceb02ae4de163ff6bc86d906d5fc6430be3318a14d7d3a41fd3919dd7bbd7e473864a0638191252d6a1993a3b776b1c333584480"},
		{Password: "000102030405060708090a0b0c0d0e0f1011", Salt: "11100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "c98aeaf8cb1d5fc9edb32090c46d3c6830e5070e62c51c114fa3c38f53e587655364b3d9150e7178ceb58c230c5b686d614086f380c0f32394b0cca54089f7c8"},
		{Password: "000102030405060708090a0b0c0d0e0f101112", Salt: "1211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "bdfa0b07748719c0b6fef0610f3a7f9830a456390e8a1985b4559e208ca93f7c01a33593f3450cbc56f0f94cab9918c8494730cfaf2bf8720280850531a579f7"},
		{Password: "000102030405060708090a0b0c0d0e0f10111213", Salt: "131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "c864771eb56f0a509340a2b2226fa4d3245485263aa8043975e486624a9417900796b9f85a14517293bbb7fa627aba47f555ad354a52fe79ce6e6302aba0d7dc"},
		{Password: "000102030405060708090a0b0c0d0e0f1011121314", Salt: "14131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "0d7453690d2fe7dce0663137a3d9d50a9a9b9116cf084f8a46671b1333f40d1d18919033e2046a0492f25479c367a0d694fec6ba86ba65b7ce28987bbb96ee12"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415", Salt: "1514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "5b36f630600d24c885f37c5c1eee082b4242c6b90f6581292159521c85ac7668e3c233f192481c7de56b146bafc292ee8511bcf596db962a2a2eaa2071b43bed"},
		{Password: "000102030405060708090a0b0c0d0e0f10111213141516", Salt: "161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "b47692aecc3e89d19de9cb3d96be5a69d279133621e139356116544ea27ab4743e5854ca0d28dd220debf90542327f5e73618775b08338ef12490395585f8bd0"},
		{Password: "000102030405060708090a0b0c0d0e0f1011121314151617", Salt: "17161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "c37fb58b753460e02946d0c60fd2db38662b83e9e78ccd71878266b923cf321d3e4f8c05c4b4a703ea7d42b8126af001dfdb466099fd746d782365377b1e0ddd"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718", Salt: "1817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "206441802ba3c27e9cb952b9b94d9474b75d0629e2ea1c23417b391b83e9c332a49a97f62a47c42b433080c527580f41dab4fa87a03b4c7aa78d438878ee8b82"},
		{Password: "000102030405060708090a0b0c0d0e0f10111213141516171819", Salt: "191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "3fa9a885db0677c0d0e2bc77b3e0cb6dc186378ffa2ba11b3d6cb319bacf3a62adfa35bfb54f3ddb9f6fb4bde3fae61dbee95dcad02a2582ef51143d5bffe747"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718191a", Salt: "1a191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "e51f4f4a323a1defeed2d860c73fee126884d82db593f85d12a5f9d551da1ac64da2a449f9b2252c5af1492be0c6672767af5af2323412043a0db4659f480276"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b", Salt: "1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "84f40da8ade63e427d326d7186366bd6756badfc485740ed36edb120e2bf6db407cb4510d4a9cb7cad28cb191568b14e3113294475e411c331413410a0e4c98d"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c", Salt: "1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "d330d017844f3ba392d98331257d6c2596d16a98b7987b33793b2b5219217200d175aa54a1dd139e412a5b6b8fd73d9110ac125a6a0e94e6191ab71938c14aac"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d", Salt: "1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "9fe96ed9fcf43505dd7a461ff465da18af8a8e0d7a23d7686c10ede19cbe7625765e63a99906ee4ff2d18a31cbc626a5ca96f7702b3aa084d149cbd8895e8819"},
		{Password: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e", Salt: "1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", Time: 2, Upgrade: 0, Mem: 2, Hash: "959135fbf1e1bd04b8b7a0285c2a295b1c126b395d89974a00d075f5451a2301644f2aaae5de67790b68d06ae4632626494a099dce1f429b457f86cf99ad9752"}}

	for _, test := range table {
		password, err := hex.DecodeString(test.Password)
		if err != nil {
			t.Error(err)
			continue
		}
		salt, err := hex.DecodeString(test.Salt)
		if err != nil {
			t.Error(err)
			continue
		}

		key, err := BATTCrypt(password, salt, test.Time, test.Upgrade, test.Mem)
		if err != nil {
			t.Error(err)
			continue
		}
		hash := hex.EncodeToString(key[:])

		if hash != test.Hash {
			t.Errorf("%q != %q for %#v", hash, test.Hash, test)
		}
	}
}

var xkcd = []byte("correct horse battery staple")
var salt = []byte("")

func doBenchmark(b *testing.B, time, upgrade, memory uint64) {
	for i := 0; i < b.N; i++ {
		_, _ = BATTCrypt(xkcd, salt, time, upgrade, memory)
	}
}

func BenchmarkT0U0M0(b *testing.B) { doBenchmark(b, 0, 0, 0) }
func BenchmarkT1U0M0(b *testing.B) { doBenchmark(b, 1, 0, 0) }
func BenchmarkT2U0M0(b *testing.B) { doBenchmark(b, 2, 0, 0) }
func BenchmarkT3U0M0(b *testing.B) { doBenchmark(b, 3, 0, 0) }
func BenchmarkT4U0M0(b *testing.B) { doBenchmark(b, 4, 0, 0) }
func BenchmarkT0U0M1(b *testing.B) { doBenchmark(b, 0, 0, 1) }
func BenchmarkT1U0M1(b *testing.B) { doBenchmark(b, 1, 0, 1) }
func BenchmarkT2U0M1(b *testing.B) { doBenchmark(b, 2, 0, 1) }
func BenchmarkT3U0M1(b *testing.B) { doBenchmark(b, 3, 0, 1) }
func BenchmarkT4U0M1(b *testing.B) { doBenchmark(b, 4, 0, 1) }
func BenchmarkT0U0M2(b *testing.B) { doBenchmark(b, 0, 0, 2) }
func BenchmarkT1U0M2(b *testing.B) { doBenchmark(b, 1, 0, 2) }
func BenchmarkT2U0M2(b *testing.B) { doBenchmark(b, 2, 0, 2) }
func BenchmarkT3U0M2(b *testing.B) { doBenchmark(b, 3, 0, 2) }
func BenchmarkT4U0M2(b *testing.B) { doBenchmark(b, 4, 0, 2) }
func BenchmarkT0U1M0(b *testing.B) { doBenchmark(b, 0, 1, 0) }
func BenchmarkT1U1M0(b *testing.B) { doBenchmark(b, 1, 1, 0) }
func BenchmarkT2U1M0(b *testing.B) { doBenchmark(b, 2, 1, 0) }
func BenchmarkT3U1M0(b *testing.B) { doBenchmark(b, 3, 1, 0) }
func BenchmarkT4U1M0(b *testing.B) { doBenchmark(b, 4, 1, 0) }
func BenchmarkT0U1M1(b *testing.B) { doBenchmark(b, 0, 1, 1) }
func BenchmarkT1U1M1(b *testing.B) { doBenchmark(b, 1, 1, 1) }
func BenchmarkT2U1M1(b *testing.B) { doBenchmark(b, 2, 1, 1) }
func BenchmarkT3U1M1(b *testing.B) { doBenchmark(b, 3, 1, 1) }
func BenchmarkT4U1M1(b *testing.B) { doBenchmark(b, 4, 1, 1) }
func BenchmarkT0U1M2(b *testing.B) { doBenchmark(b, 0, 1, 2) }
func BenchmarkT1U1M2(b *testing.B) { doBenchmark(b, 1, 1, 2) }
func BenchmarkT2U1M2(b *testing.B) { doBenchmark(b, 2, 1, 2) }
func BenchmarkT3U1M2(b *testing.B) { doBenchmark(b, 3, 1, 2) }
func BenchmarkT4U1M2(b *testing.B) { doBenchmark(b, 4, 1, 2) }
