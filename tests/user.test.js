import { expect } from 'chai';
import add from '../utils.js'; // Adjust path as needed

describe('Add Function', () => {
  it('should return 2 when called', () => {
    const result = add();
    expect(result).to.equal(2);
  });
});
