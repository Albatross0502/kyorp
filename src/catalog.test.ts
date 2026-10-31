import test from 'node:test';
import assert from 'node:assert/strict';

const SHIPPING_THRESHOLD_INR = 1999;
const FLAT_SHIPPING_INR = 150;

function calculateShipping(subtotalINR: number): number {
  return subtotalINR >= SHIPPING_THRESHOLD_INR ? 0 : FLAT_SHIPPING_INR;
}

function convertCurrency(amountINR: number, rate: number): number {
  return Math.round(amountINR * rate * 100) / 100;
}

test('free shipping threshold rule applies properly', () => {
  assert.equal(calculateShipping(1999), 0);
  assert.equal(calculateShipping(2500), 0);
  assert.equal(calculateShipping(1998), 150);
  assert.equal(calculateShipping(0), 150);
});

test('currency conversion matches standard rates', () => {
  const usdRate = 0.012;
  const gbpRate = 0.0095;
  assert.equal(convertCurrency(1000, usdRate), 12);
  assert.equal(convertCurrency(1000, gbpRate), 9.5);
});
