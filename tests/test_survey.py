"""Protocol-level tests: correctness against a plaintext baseline, and the gating rules in Part 2 section 3.1."""

import random
import unittest

from paillier import encrypt, generate_keypair
from survey import (
    Analyst,
    AggregationServer,
    IntegrityWarning,
    ReleaseError,
    SubmissionError,
    SurveyParams,
    plaintext_stats,
    respondent_submit,
)

PARAMS = SurveyParams(num_questions=3, k_threshold=5)


class SurveyFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pk, cls.sk = generate_keypair(256)  # small key: test speed only

    def make_server(self, n_people):
        people = [f"p{i}" for i in range(n_people)]
        server = AggregationServer(self.pk, PARAMS, set(people))
        return server, people

    def submit_all(self, server, people, answers):
        for pid, row in zip(people, answers):
            server.accept(pid, respondent_submit(self.pk, row, PARAMS))


class TestCorrectness(SurveyFixture):
    def test_mean_and_variance_match_plaintext(self):
        rng = random.Random(7)
        answers = [[rng.randint(1, 5) for _ in range(PARAMS.num_questions)] for _ in range(12)]
        server, people = self.make_server(12)
        self.submit_all(server, people, answers)
        analyst = Analyst(self.pk, self.sk, PARAMS)
        got = analyst.decrypt_release(server.release())
        want = plaintext_stats(answers)
        self.assertEqual(got, want)
        for g, w in zip(got, want):
            self.assertEqual(g.mean, w.mean)
            self.assertEqual(g.variance, w.variance)

    def test_known_small_example(self):
        answers = [[1, 5, 3], [3, 5, 3], [5, 5, 3], [3, 5, 3], [3, 5, 3]]
        server, people = self.make_server(5)
        self.submit_all(server, people, answers)
        stats = Analyst(self.pk, self.sk, PARAMS).decrypt_release(server.release())
        self.assertEqual(stats[0].sum_x, 15)
        self.assertEqual(stats[0].sum_x2, 1 + 9 + 25 + 9 + 9)
        self.assertEqual(stats[1].variance, 0)  # everyone answered 5
        self.assertEqual(stats[2].mean, 3)

    def test_plaintext_baseline_on_same_data(self):
        answers = [[2, 4, 1], [2, 4, 1]]
        s = plaintext_stats(answers)
        self.assertEqual(s[0].mean, 2)
        self.assertEqual(s[0].variance, 0)
        self.assertEqual(s[1].mean, 4)


class TestGating(SurveyFixture):
    def test_below_threshold_no_release(self):
        server, people = self.make_server(PARAMS.k_threshold)
        self.submit_all(server, people[:-1], [[1, 1, 1]] * (PARAMS.k_threshold - 1))
        with self.assertRaises(ReleaseError):
            server.release()

    def test_release_is_single_and_repeatable(self):
        server, people = self.make_server(5)
        self.submit_all(server, people, [[2, 2, 2]] * 5)
        first = server.release()
        second = server.release()
        self.assertIs(first, second)

    def test_no_submission_after_release(self):
        server, people = self.make_server(6)
        self.submit_all(server, people[:5], [[2, 2, 2]] * 5)
        server.release()
        with self.assertRaises(ReleaseError):
            server.accept(people[5], respondent_submit(self.pk, [1, 1, 1], PARAMS))

    def test_duplicate_rejected(self):
        server, people = self.make_server(2)
        sub = respondent_submit(self.pk, [1, 2, 3], PARAMS)
        server.accept(people[0], sub)
        with self.assertRaises(SubmissionError):
            server.accept(people[0], sub)

    def test_ineligible_rejected(self):
        server, _ = self.make_server(1)
        with self.assertRaises(SubmissionError):
            server.accept("intruder", respondent_submit(self.pk, [1, 2, 3], PARAMS))

    def test_wrong_shape_rejected(self):
        server, people = self.make_server(1)
        sub = respondent_submit(self.pk, [1, 2, 3], PARAMS)
        with self.assertRaises(SubmissionError):
            server.accept(people[0], sub[:-1])
        with self.assertRaises(SubmissionError):
            server.accept(people[0], sub + [encrypt(self.pk, 1)])

    def test_malformed_ciphertext_rejected(self):
        server, people = self.make_server(1)
        sub = respondent_submit(self.pk, [1, 2, 3], PARAMS)
        sub[0] = 0
        with self.assertRaises(SubmissionError):
            server.accept(people[0], sub)
        sub[0] = self.pk.n  # shares a factor with n^2, so not a unit
        with self.assertRaises(SubmissionError):
            server.accept(people[0], sub)

    def test_out_of_range_answer_rejected_by_honest_client(self):
        with self.assertRaises(ValueError):
            respondent_submit(self.pk, [1, 2, 6], PARAMS)
        with self.assertRaises(ValueError):
            respondent_submit(self.pk, [1, 2], PARAMS)


class TestIntegrityBound(SurveyFixture):
    def test_out_of_range_value_detected_but_not_attributed(self):
        # A cheating respondent submits Enc(1000) for question 1. The totals fall outside 0..5N.
        server, people = self.make_server(5)
        self.submit_all(server, people[:4], [[1, 1, 1]] * 4)
        cheat = respondent_submit(self.pk, [1, 1, 1], PARAMS)
        cheat[0] = encrypt(self.pk, 1000)
        server.accept(people[4], cheat)
        with self.assertRaises(IntegrityWarning):
            Analyst(self.pk, self.sk, PARAMS).decrypt_release(server.release())


if __name__ == "__main__":
    unittest.main()
