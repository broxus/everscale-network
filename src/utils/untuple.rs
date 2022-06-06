use frunk_core::hlist::{HCons, HNil};

pub trait HConsUntuple {
    type Output;
    fn untuple(self) -> Self::Output;
}

impl<T1, T2> HConsUntuple for HCons<T2, HCons<T1, HNil>> {
    type Output = (T1, T2);

    fn untuple(self) -> Self::Output {
        (self.tail.head, self.head)
    }
}

impl<T1, T2, T3> HConsUntuple for HCons<T3, HCons<T2, HCons<T1, HNil>>> {
    type Output = (T1, T2, T3);

    fn untuple(self) -> Self::Output {
        (self.tail.tail.head, self.tail.head, self.head)
    }
}

impl<T1, T2, T3, T4> HConsUntuple for HCons<T4, HCons<T3, HCons<T2, HCons<T1, HNil>>>> {
    type Output = (T1, T2, T3, T4);

    fn untuple(self) -> Self::Output {
        (
            self.tail.tail.tail.head,
            self.tail.tail.head,
            self.tail.head,
            self.head,
        )
    }
}

impl<T1, T2, T3, T4, T5> HConsUntuple
    for HCons<T5, HCons<T4, HCons<T3, HCons<T2, HCons<T1, HNil>>>>>
{
    type Output = (T1, T2, T3, T4, T5);

    fn untuple(self) -> Self::Output {
        (
            self.tail.tail.tail.tail.head,
            self.tail.tail.tail.head,
            self.tail.tail.head,
            self.tail.head,
            self.head,
        )
    }
}

impl<T1, T2, T3, T4, T5, T6> HConsUntuple
    for HCons<T6, HCons<T5, HCons<T4, HCons<T3, HCons<T2, HCons<T1, HNil>>>>>>
{
    type Output = (T1, T2, T3, T4, T5, T6);

    fn untuple(self) -> Self::Output {
        (
            self.tail.tail.tail.tail.tail.head,
            self.tail.tail.tail.tail.head,
            self.tail.tail.tail.head,
            self.tail.tail.head,
            self.tail.head,
            self.head,
        )
    }
}
